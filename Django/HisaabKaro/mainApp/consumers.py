import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth.models import User
from django.utils import timezone
from .models import Group, ChatMessage, ChatMessageRead, GroupMembership


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
                                'sender_id': message.sender.id,
                                'sender_name': message.get_sender_name(),
                                'timestamp': message.timestamp.isoformat(),
                                'is_own': False  # Will be updated in chat_message method
                            }
                        }
                    )
            
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
            
            messages = ChatMessage.objects.filter(
                group=group,
                timestamp__gte=join_date,
                is_deleted=False
            ).select_related('sender').order_by('-timestamp')[:50]
            
            return [{
                'id': msg.id,
                'content': msg.content,
                'sender_id': msg.sender.id,
                'sender_name': msg.get_sender_name(),
                'timestamp': msg.timestamp.isoformat(),
                'is_own': msg.sender.id == self.user.id
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
