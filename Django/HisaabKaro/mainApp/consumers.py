import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth.models import User
from django.utils import timezone
from .models import Group, ChatMessage, ChatMessageRead, GroupMembership


class UserNotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user_id = self.scope['url_route']['kwargs']['user_id']
        self.user = self.scope['user']
        
        if not self.user.is_authenticated or str(self.user.id) != self.user_id:
            await self.close()
            return
        
        self.user_group_name = f'user_{self.user_id}'
        
        # Join user notification group
        await self.channel_layer.group_add(
            self.user_group_name,
            self.channel_name
        )
        
        await self.accept()
    
    async def disconnect(self, close_code):
        # Leave user notification group
        await self.channel_layer.group_discard(
            self.user_group_name,
            self.channel_name
        )
    
    async def unread_count_update(self, event):
        # Send unread count update to WebSocket
        await self.send(text_data=json.dumps({
            'type': 'unread_count_update',
            'group_id': event['group_id'],
            'unread_count': event['unread_count']
        }))
    
    async def notification_update(self, event):
        # Send notification update to WebSocket
        await self.send(text_data=json.dumps({
            'type': 'notification_update',
            'unread_count': event['unread_count']
        }))


class GroupChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.group_id = self.scope['url_route']['kwargs']['group_id']
        self.group_room_name = f'group_chat_{self.group_id}'
        self.user = self.scope['user']
        
        if not self.user.is_authenticated:
            await self.close()
            return
        
        # Check if user is member of this group
        is_member = await self.check_group_membership()
        if not is_member:
            await self.close()
            return
        
        # Join room group
        await self.channel_layer.group_add(
            self.group_room_name,
            self.channel_name
        )
        
        await self.accept()
        
        # Send recent messages to newly connected user
        await self.send_recent_messages()
    
    async def disconnect(self, close_code):
        # Leave room group
        await self.channel_layer.group_discard(
            self.group_room_name,
            self.channel_name
        )
    
    async def receive(self, text_data):
        try:
            text_data_json = json.loads(text_data)
            message_type = text_data_json.get('type', 'chat_message')
            
            if message_type == 'chat_message':
                message_content = text_data_json['message'].strip()
                
                if not message_content:
                    return
                
                # Save message to database
                message = await self.save_message(message_content)
                
                if message:
                    # Send message to room group
                    await self.channel_layer.group_send(
                        self.group_room_name,
                        {
                            'type': 'chat_message',
                            'message': {
                                'id': message.id,
                                'content': message.content,
                                'message_type': message.message_type,
                                'image_url': message.image.url if message.image else None,
                                'sender_id': message.sender.id,
                                'sender_name': message.get_sender_name(),
                                'timestamp': message.timestamp.isoformat(),
                                'edited_at': message.edited_at.isoformat() if message.edited_at else None,
                                'is_own': False  # Will be updated in chat_message method
                            }
                        }
                    )
                    
                    # Send unread count update to all group members
                    await self.broadcast_unread_counts()
            
            elif message_type == 'mark_read':
                message_ids = text_data_json.get('message_ids', [])
                await self.mark_messages_read(message_ids)
                
        except json.JSONDecodeError:
            pass
        except Exception as e:
            print(f"Error in receive: {e}")
    
    async def chat_message(self, event):
        message = event['message']
        # Mark if this is user's own message
        message['is_own'] = message['sender_id'] == self.user.id
        
        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'type': 'chat_message',
            'message': message
        }))
    
    @database_sync_to_async
    def check_group_membership(self):
        try:
            group = Group.objects.get(id=self.group_id)
            return group.members.filter(id=self.user.id).exists()
        except Group.DoesNotExist:
            return False
    
    @database_sync_to_async
    def save_message(self, content):
        try:
            group = Group.objects.get(id=self.group_id)
            
            # Check if user joined the group (for access control)
            membership = GroupMembership.objects.filter(
                user=self.user, 
                group=group
            ).first()
            
            if not membership:
                # Create membership record if doesn't exist
                membership = GroupMembership.objects.create(
                    user=self.user,
                    group=group
                )
            
            message = ChatMessage.objects.create(
                group=group,
                sender=self.user,
                content=content
            )
            return message
        except Exception as e:
            print(f"Error saving message: {e}")
            return None
    
    @database_sync_to_async
    def get_recent_messages(self):
        try:
            group = Group.objects.get(id=self.group_id)
            
            # Get user's join date to filter messages
            membership = GroupMembership.objects.filter(
                user=self.user, 
                group=group
            ).first()
            
            join_date = membership.joined_at if membership else timezone.now()
            
            # Get messages from join date onwards (not all historical messages)
            messages = ChatMessage.objects.filter(
                group=group,
                timestamp__gte=join_date,
                is_deleted=False
            ).select_related('sender').order_by('-timestamp')[:50]
            
            return [{
                'id': msg.id,
                'content': msg.content,
                'message_type': msg.message_type,
                'image_url': msg.image.url if msg.image else None,
                'sender_id': msg.sender.id,
                'sender_name': msg.get_sender_name(),
                'timestamp': msg.timestamp.isoformat(),
                'edited_at': msg.edited_at.isoformat() if msg.edited_at else None,
                'is_own': msg.sender.id == self.user.id,
                'can_edit': msg.can_edit(self.user),
                'can_delete': msg.can_delete(self.user)
            } for msg in reversed(messages)]
        except Exception as e:
            print(f"Error getting recent messages: {e}")
            return []
    
    async def send_recent_messages(self):
        messages = await self.get_recent_messages()
        
        await self.send(text_data=json.dumps({
            'type': 'recent_messages',
            'messages': messages
        }))
    
    @database_sync_to_async
    def mark_messages_read(self, message_ids):
        try:
            for message_id in message_ids:
                try:
                    message = ChatMessage.objects.get(id=message_id)
                    ChatMessageRead.objects.get_or_create(
                        message=message,
                        user=self.user
                    )
                except ChatMessage.DoesNotExist:
                    continue
        except Exception as e:
            print(f"Error marking messages as read: {e}")

    async def broadcast_unread_counts(self):
        """Broadcast unread count updates to all group members"""
        try:
            group = await self.get_group()
            if group:
                members = await self.get_group_members(group)
                for member in members:
                    unread_count = await self.get_unread_count_for_user(member)
                    await self.channel_layer.group_send(
                        f"user_{member.id}",
                        {
                            'type': 'unread_count_update',
                            'group_id': self.group_id,
                            'unread_count': unread_count
                        }
                    )
        except Exception as e:
            print(f"Error broadcasting unread counts: {e}")

    @database_sync_to_async
    def get_group(self):
        try:
            return Group.objects.get(id=self.group_id)
        except Group.DoesNotExist:
            return None

    @database_sync_to_async
    def get_group_members(self, group):
        return list(group.members.all())

    @database_sync_to_async
    def get_unread_count_for_user(self, user):
        try:
            unread_messages = ChatMessage.objects.filter(
                group_id=self.group_id,
                is_deleted=False
            ).exclude(
                read_by__user=user
            ).exclude(
                sender=user  # Exclude own messages
            )
            return min(unread_messages.count(), 100)  # Cap at 100
        except Exception as e:
            print(f"Error getting unread count for user {user.id}: {e}")
            return 0
