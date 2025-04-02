# Finance Manager

A comprehensive personal finance management system built with Flask and MongoDB.

## Features

- **Expense & Income Tracking**: Record and manage all your transactions with ease.
- **Budget Management**: Set budgets for different categories and track spending.
- **Advanced Reporting**: Visualize your finances with charts and detailed reports.
- **Customization**: Configure currency, date format, categories, and more.
- **Email Notifications**: Receive timely updates about your financial situation.
- **Dark Mode Support**: Work with your finances day or night with theme support.
- **Admin Log Viewer**: Secure dashboard for viewing and managing application logs.
- **User Management**: Admin panel for managing users and their privileges.

## Requirements

- Python 3.9+
- MongoDB
- Resend API Key (for email functionality)

## Installation

### Local Development Setup

1. Clone the repository:
   ```
   git clone https://github.com/WhoIsJayD/Finance-Manager
   cd Finance-Manager
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Unix/Linux/Mac
   venv\Scripts\activate     # On Windows
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Create a `.env` file by copying the example:
   ```
   cp .env.example .env       # On Unix/Linux/Mac
   copy .env.example .env     # On Windows
   ```
   Then edit the file to configure your environment variables.

5. Set up MongoDB:
   - Ensure MongoDB is running on localhost:27017 or update the connection string in your `.env` file

6. Run the application:
   ```
   flask run
   ```
   
## Production Deployment

### Using Docker

The easiest way to deploy the Finance Manager in production is using Docker and Docker Compose.

1. Clone the repository and navigate to the project folder
2. Create a `.env` file with production settings:
   ```
   cp .env.example .env       # On Unix/Linux/Mac
   copy .env.example .env     # On Windows
   ```
   
   Update the following variables for production:
   ```
   FLASK_ENV=production
   SECRET_KEY=<generate-a-secure-random-key>
   RESEND_API_KEY=<your-resend-api-key>
   ```
   
3. Build and run the containers:
   ```
   docker-compose up -d
   ```

This will start the application with Gunicorn and MongoDB, with proper isolation and volume persistence.

### Manual Deployment - Linux/macOS

If you prefer to deploy without Docker on Linux or macOS:

1. Set up a production MongoDB instance
2. Configure environment variables for production
3. Install dependencies: `pip install -r requirements.txt`
4. Run with Gunicorn:
   ```
   gunicorn --bind 0.0.0.0:5000 app:app --workers=4 --threads=2 --timeout=60
   ```

5. Set up a reverse proxy like Nginx to serve the application

### Manual Deployment - Windows

For Windows deployment without Docker:

1. Set up a production MongoDB instance
2. Configure environment variables for production
3. Install dependencies: `pip install -r requirements.txt`
4. Run with Waitress using the provided script:
   ```
   python run_server.py
   ```

5. For a production environment, consider setting up IIS as a reverse proxy

## Security Considerations

The application implements several security features:

- Password hashing with bcrypt
- Rate limiting for login and registration endpoints
- Secure session cookies
- CSRF protection for forms
- Email notifications for security-sensitive actions
- Input validation and sanitization

For production deployments, we recommend:

- Always use HTTPS with a valid SSL certificate
- Set up proper firewall rules
- Regularly backup your MongoDB database
- Keep all dependencies updated
- Use a strong SECRET_KEY value

## Email System

The Finance Manager includes a robust email notification system for keeping users informed about their finances.

### Setting Up Email

1. Sign up for an account at [Resend](https://resend.com) to get an API key.
2. Set the API key as an environment variable:
   ```
   RESEND_API_KEY=your_resend_api_key
   ```
3. Customize the sender email in your `.env` file if needed (default is "Finance Manager <no-reply@finance-manager.com>").

### Email Features

- **Weekly Summaries**: Users receive a weekly overview of income, expenses, and top spending categories.
- **Monthly Reports**: Detailed monthly financial reports.
- **Budget Alerts**: Notifications when users approach or exceed budget limits.
- **Security Alerts**: Email notifications for password changes and account updates.
- **Transaction Confirmations**: Confirmations for large or important transactions.

### User Preferences

Users can customize which email notifications they wish to receive through the Settings page:

1. Navigate to the Settings page
2. Go to the "Email Notifications" tab
3. Check/uncheck desired notification types
4. Save preferences

### Testing Email Functionality

To test if email sending works correctly:

1. Log in to your account
2. Go to the Settings page
3. Navigate to the "Email Notifications" tab
4. Click "Send Test Email"

## Performance Optimization

The system is optimized for high performance and can handle many concurrent users:

### Database Optimization

- Proper MongoDB indexing for fast queries
- Query projection to retrieve only necessary data
- Client-side calculations to reduce database load
- Caching of frequently accessed data

### Email System Optimization

- Background processing of emails via worker threads
- Email queue for handling high volume
- Graceful degradation if email service is unavailable

## Monitoring and Logging

The application includes comprehensive logging:

- Application logs stored in the `logs` directory
- Separate log streams for application and email functionality
- Log rotation to prevent disk space issues
- Error tracking and reporting

You can monitor the application using:

- The `/security-check` endpoint (requires login)
- The `/admin/logs` endpoint for viewing detailed logs (requires admin login)
- Log analysis
- MongoDB status checks

### Admin Log Viewer

The application includes a secure web interface for viewing and managing logs:

1. Access the log viewer at `/admin/logs` (admin privileges required)
2. View application logs, email logs, or server logs
3. Filter logs using the search function
4. Navigate through log pages with pagination
5. Download logs for offline analysis
6. Clear logs with admin password confirmation (logs are backed up before clearing)

For security, the log viewer requires:
- A valid user account with admin privileges
- The ADMIN_PASSWORD environment variable to be set for clearing logs

## Admin System

Finance Manager includes a comprehensive admin system for managing the application and users.

### Initial Admin Setup

When first deploying the application, you need to initialize an admin user:

1. Set the `ADMIN_SETUP_CODE` in your `.env` file to a secure random string
2. Navigate to `/initialize-admin` in your browser
3. Enter the setup code from your `.env` file
4. Provide an email address and password for the admin user
5. Submit the form to create the first admin

### Admin Features

Once you have admin access, you can:

1. **Manage Users**: View all users and grant/revoke admin privileges at `/admin/users`
2. **View System Logs**: Access application logs, email logs, and server logs at `/admin/logs`
3. **Clear Logs**: Clear and backup log files as needed (requires admin password confirmation)

### Granting Admin Privileges

To grant admin privileges to additional users:

1. Log in with an existing admin account
2. Navigate to `/admin/users`
3. Click "Make Admin" next to the desired user
4. Enter the admin password from your `.env` file to confirm
5. The user will now have admin access

### Admin Security

The admin system is secured through multiple layers:

1. Admin privileges are checked on all admin routes using `@admin_required` decorator
2. Sensitive operations (like changing admin status) require admin password confirmation
3. All admin actions are logged for accountability
4. Admin-only routes redirect non-admin users to the dashboard with an error message

## Troubleshooting

### Windows-Specific Issues

If you encounter issues installing dependencies on Windows:

1. Make sure you have a C++ compiler installed if installing bcrypt or cryptography packages
2. Consider using MongoDB Atlas instead of a local MongoDB instance
3. If uwsgi installation fails, it's not needed on Windows - the application will use Waitress instead

### Email Issues

If emails are not being sent:

1. Check if Resend API key is correctly set
2. Verify user has an email address in their profile
3. Ensure user has enabled the specific notification type
4. Check the email logs

### Database Performance

If the application feels slow:

1. Ensure MongoDB indexes are created
2. Check for inefficient queries in the logs
3. Consider increasing cache TTLs for stable data

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Tech Stack

- **Backend**: Python, Flask
- **Database**: MongoDB with PyMongo
- **Frontend**: HTML, CSS, JavaScript, Bootstrap 5
- **Charts**: Chart.js

## Project Structure

```
finance_manager/
├── app.py                  # Main application file
├── requirements.txt        # Python dependencies
├── static/                 # Static files
│   ├── css/                # CSS styles
│   │   └── style.css       # Custom styles
│   └── js/                 # JavaScript files
│       └── main.js         # Common JS functionality
└── templates/              # HTML templates
    ├── base.html           # Base template
    ├── index.html          # Landing page
    ├── login.html          # Login page
    ├── register.html       # Registration page
    ├── dashboard.html      # User dashboard
    ├── transactions.html   # Transactions list
    ├── add_transaction.html # Add transaction form
    ├── edit_transaction.html # Edit transaction form
    ├── budgets.html        # Budget management
    ├── settings.html       # User settings
    └── reports.html        # Financial reports
```

## API Endpoints

- `/api/transactions` - Get filtered transactions
- `/api/reports/category` - Get spending by category
- `/api/reports/monthly` - Get monthly income and expense data
- `/api/budget/progress` - Get budget progress data

## Database Schema

**Users Collection**
```
{
  _id: ObjectId,
  email: String,
  password: String (hashed),
  created_at: DateTime
}
```

**Transactions Collection**
```
{
  _id: ObjectId,
  user_id: String,
  amount: Float,
  description: String,
  category: String,
  type: String (income/expense),
  date: DateTime,
  tags: [String], (optional)
  payment_method: String, (optional)
  notes: String, (optional)
  created_at: DateTime,
  updated_at: DateTime (optional)
}
```

**Budgets Collection**
```
{
  _id: ObjectId,
  user_id: String,
  category: String,
  amount: Float,
  created_at: DateTime,
  updated_at: DateTime (optional)
}
```

**Settings Collection**
```
{
  _id: ObjectId,
  user_id: String,
  currency: String,
  date_format: String,
  theme: String (light/dark),
  dashboard_widgets: [String],
  default_categories: {
    income: [String],
    expense: [String]
  },
  created_at: DateTime,
  updated_at: DateTime (optional)
}
```

## Advanced Features

### Budget Management
- Set monthly budgets by category
- Visual indicators for budget progress
- Alerts for exceeding budget thresholds
- Monthly budget summaries

### Custom Categories
- Define and customize your own income and expense categories
- Default categories provided for quick setup
- Ability to add, rename, and remove categories

### Transaction Tagging
- Add custom tags to transactions
- Filter and search by tags
- Group reports by tags

### User Preferences
- Choose currency format
- Select date format
- Switch between light and dark themes
- Customize dashboard layout

## License

MIT License

## Acknowledgements

- Bootstrap 5 for the UI components
- Chart.js for the data visualizations
- MongoDB for the database
- Flask for the web framework 