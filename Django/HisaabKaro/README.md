# 💰 HisaabKaro - Smart Expense Management

<div align="center">

![HisaabKaro Logo](https://img.shields.io/badge/HisaabKaro-Expense%20Manager-blue?style=for-the-badge&logo=money-bill&logoColor=white)

**Your go-to budget management app for tracking expenses and splitting bills with friends!**

[![Django](https://img.shields.io/badge/Django-4.0+-092E20?style=flat&logo=django&logoColor=white)](https://djangoproject.com/)
[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org/)
[![JavaScript](https://img.shields.io/badge/JavaScript-ES6+-F7DF1E?style=flat&logo=javascript&logoColor=black)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![Bootstrap](https://img.shields.io/badge/Bootstrap-5.0+-7952B3?style=flat&logo=bootstrap&logoColor=white)](https://getbootstrap.com/)

</div>

---

## 🚀 What is HisaabKaro?

HisaabKaro is a comprehensive expense management platform that transforms how you handle money with friends, family, and colleagues. Whether you're tracking your monthly spending patterns, splitting bills after a group meal, setting up automatic reminders for dues, or coordinating with your group through real-time chat - HisaabKaro is your one-stop financial companion.

## 📸 App Preview

<div align="center">

> **💡 Pro Tip**: Experience HisaabKaro live by following the [Quick Start Guide](#-quick-start-guide) below!

### 🎯 **Key Workflows**

| 💰 **Expense Management** | 💬 **Group Chat** | 📊 **Analytics Dashboard** |
|:-------------------------:|:------------------:|:---------------------------:|
| *Create and split expenses with ease* | *Coordinate with real-time messaging* | *Visualize spending patterns* |

</div>

---

## ✨ Key Features Overview

<table>
<tr>
<td width="50%">

### 💸 **Smart Split System**
- **Flexible Splitting Options**: Equal, percentage-based, or custom amounts
- **Multi-Currency Support**: PKR with automatic formatting
- **Real-time Calculations**: Instant updates as you modify splits
- **Debt Tracking**: Keep track of who owes what to whom

</td>
<td width="50%">

### 💬 **Real-time Chat System**
- **Group Messaging**: Coordinate with your expense groups
- **Image Sharing**: Share receipts and photos instantly
- **Message Editing**: Fix typos with edit functionality
- **Real-time Updates**: WebSocket-powered instant messaging

</td>
</tr>
<tr>
<td width="50%">

### 🔔 **Smart Notification System**
- **Automatic Reminders**: Never forget to pay or collect dues
- **Payment Reminders**: Gentle nudges for pending payments with 24-hour cooldown
- **Real-time Alerts**: Instant notifications for group activities
- **Expense Updates**: Get notified when expenses are added/modified
- **Settlement Tracking**: Alerts when debts are settled

</td>
<td width="50%">

### 📊 **Advanced Chart System**
- **Visual Analytics**: Beautiful charts and graphs
- **Spending Patterns**: Track your expense trends over time
- **Category Breakdown**: See where your money goes
- **Group Insights**: Analyze group spending patterns

</td>
</tr>
</table>

---

## 🎯 Core Systems Deep Dive

### 💸 Split System - *Fairness Made Simple*

The heart of HisaabKaro lies in its intelligent splitting mechanism:

#### **Split Types Available:**
- **🟰 Equal Split**: Divide expenses equally among all participants
- **📊 Percentage Split**: Allocate based on custom percentages (perfect for different income levels)
- **💰 Custom Amount Split**: Set exact amounts for each person

#### **How It Works:**
```
1. Create an expense → 2. Choose participants → 3. Select split method → 4. Automatic calculation
```

#### **Smart Features:**
- ✅ **Real-time Validation**: Ensures splits add up to 100%
- ✅ **Debt Optimization**: Minimizes the number of transactions needed
- ✅ **Multi-step Editing**: Modify splits without losing data
- ✅ **Settlement Tracking**: Mark debts as settled with confirmation

---

### 💬 Chat System - *Stay Connected*

Built-in communication keeps your groups coordinated:

#### **Core Features:**
- **📱 Real-time Messaging**: Powered by Django Channels and WebSockets
- **🖼️ Image Sharing**: Upload and share receipts or photos
- **✏️ Message Editing**: Fix mistakes with in-place editing
- **🗑️ Message Deletion**: Remove messages you sent

#### **Technical Implementation:**
```
WebSocket Connection → Real-time Updates → Message Persistence → Image Storage
```

#### **User Experience:**
- **Instant Delivery**: Messages appear immediately across all devices
- **Visual Receipts**: Share photos of bills and receipts
- **Group Coordination**: Plan expenses and discuss splits in real-time

---

### 🔔 Notification System - *Never Miss a Beat*

Stay informed with intelligent notifications:

#### **Notification Types:**
- **💰 Expense Alerts**: When new expenses are added to your groups
- **💸 Settlement Reminders**: When you owe money or someone owes you
- **� Payment Reminders**: Send gentle reminders to users who owe you money
- **�👥 Group Updates**: Member additions, removals, and role changes
- **✅ Payment Confirmations**: When debts are marked as settled

#### **Payment Reminder System:**
- **📧 Email Reminders**: Send professional email reminders to debtors
- **📱 In-App Reminders**: Send instant notifications within the app
- **⏰ 24-Hour Cooldown**: Prevents spam with automatic cooldown period
- **🎯 Smart Targeting**: Automatically identifies who owes you money

#### **Delivery Channels:**
- **🌐 In-app Notifications**: Real-time browser notifications
- **🔴 Unread Indicators**: Visual badges for unread notifications
- **📱 Push Notifications**: Stay updated even when away

#### **Smart Logic:**
```
Event Trigger → Notification Generation → Real-time Delivery → Read Status Tracking
```

---

### 🔔 Payment Reminder System - *Gentle Nudges for Outstanding Debts*

HisaabKaro includes a sophisticated reminder system to help you collect outstanding payments without being pushy:

#### **How It Works:**
```
1. View Balance → 2. Click "Remind" → 3. Select User (if multiple) → 4. Choose Method → 5. Send Reminder
```

#### **Smart Features:**
- **🎯 Auto-Detection**: Automatically shows "Remind" button only when others owe you money
- **👥 Multi-User Support**: Select specific users when multiple people owe you
- **📧 Dual Delivery**: Choose between email or in-app notifications
- **⏰ Cooldown Protection**: 24-hour waiting period prevents reminder spam
- **💬 Professional Tone**: Gentle, friendly reminder messages

#### **Reminder Methods:**
- **📧 Email Reminder**: Professional email sent to debtor's registered email
- **📱 In-App Notification**: Instant notification within the HisaabKaro app

#### **User Experience:**
```
Debt Detected → Remind Button Available → Method Selection → Delivery → 24h Cooldown Active
```

---

### 📊 Chart System - *Insights at a Glance*

Visualize your financial data with interactive charts:

#### **Chart Types:**
- **📈 Line Charts**: Track spending trends over time
- **🥧 Pie Charts**: Category-wise expense breakdown
- **📊 Bar Charts**: Monthly/weekly spending comparisons
- **💹 Trend Analysis**: Identify spending patterns

#### **Analytics Features:**
- **🎯 Personal Insights**: Your individual spending patterns
- **👥 Group Analytics**: Collective group expense analysis
- **📅 Time-based Filtering**: View data by week, month, or custom periods
- **💰 Category Breakdown**: See exactly where your money goes

#### **Interactive Elements:**
```
Hover for Details → Click to Drill Down → Filter by Date/Category → Export Data
```

---

## 🛠️ Technical Architecture

<details>
<summary><strong>🔧 Tech Stack</strong></summary>

### Backend
- **Framework**: Django 4.0+
- **Database**: SQLite (Development) / PostgreSQL (Production)
- **Real-time**: Django Channels + WebSockets
- **Authentication**: Django's built-in auth system

### Frontend
- **UI Framework**: Bootstrap 5
- **JavaScript**: Vanilla ES6+ with modern features
- **Charts**: Chart.js for data visualization
- **Styling**: Custom CSS with dark mode support

### Key Libraries
- **Django Channels**: WebSocket support for real-time features
- **Pillow**: Image processing for file uploads
- **Chart.js**: Interactive and responsive charts

</details>

<details>
<summary><strong>🏗️ Project Structure</strong></summary>

```
HisaabKaro/
├── mainApp/                 # Core application
│   ├── models.py           # Database models
│   ├── views.py            # Business logic
│   ├── templates/          # HTML templates
│   ├── static/             # CSS, JS, images
│   └── management/         # Custom Django commands
├── HisaabKaro/             # Project settings
├── static/                 # Static files collection
├── media/                  # User uploaded files
└── requirements.txt        # Python dependencies
```

</details>

---

## 🚀 Quick Start Guide

### 1. **Clone the Repository**
```bash
git clone https://github.com/Usman-Amin19/Projects.git
cd Projects/Django/HisaabKaro
```

### 2. **Set Up Virtual Environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. **Install Dependencies**
```bash
pip install -r requirements.txt
```

### 4. **Database Setup**
```bash
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
```

### 5. **Run the Application**
```bash
python manage.py runserver
```

### 6. **Access the App**
Open your browser and navigate to `http://127.0.0.1:8000`

---

## 🎮 How to Use

### 💰 **Creating Your First Expense**
1. **Create a Group**: Start by creating an expense group
2. **Add Members**: Invite friends via email or username
3. **Add Expense**: Enter expense details and amount
4. **Choose Split**: Select how to divide the expense
5. **Track Settlements**: Monitor who owes what

### 💬 **Using the Chat System**
1. **Open Group Chat**: Click on any group to access chat
2. **Send Messages**: Type and send instant messages
3. **Share Images**: Upload receipts or photos
4. **Edit Messages**: Click to edit your own messages

### 📊 **Viewing Analytics**
1. **Access Charts**: Navigate to the analytics section
2. **Filter Data**: Choose date ranges and categories
3. **Analyze Trends**: Identify spending patterns
4. **Export Data**: Download reports for external use

---

## 🌟 Advanced Features

<details>
<summary><strong>🔧 Multi-step Expense Editing</strong></summary>

- Edit expenses across multiple steps without losing data
- Modify participants, amounts, and split methods
- Real-time validation and error handling
- Session-based data persistence

</details>

<details>
<summary><strong>🎨 Dark Mode Support</strong></summary>

- Automatic theme detection based on system preferences
- Manual theme toggle option
- Consistent design across all components
- Eye-friendly interface for all lighting conditions

</details>

<details>
<summary><strong>📱 Responsive Design</strong></summary>

- Mobile-first approach
- Touch-friendly interface
- Optimized for all screen sizes
- Progressive Web App capabilities

</details>

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. **🍴 Fork the repository**
2. **🌿 Create a feature branch**: `git checkout -b feature/AmazingFeature`
3. **💾 Commit your changes**: `git commit -m 'Add some AmazingFeature'`
4. **📤 Push to the branch**: `git push origin feature/AmazingFeature`
5. **🔄 Open a Pull Request**

### 📝 Development Guidelines
- Follow PEP 8 for Python code
- Use meaningful commit messages
- Add tests for new features
- Update documentation as needed

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Django Community** for the amazing framework
- **Bootstrap Team** for the UI components
- **Chart.js Contributors** for the charting library
- **All Contributors** who help make HisaabKaro better

---

<div align="center">

**Made with ❤️ for better expense management**

[⭐ Star this repo](https://github.com/Usman-Amin19/Projects) | [🐛 Report Bug](https://github.com/Usman-Amin19/Projects/issues) | [💡 Request Feature](https://github.com/Usman-Amin19/Projects/issues)