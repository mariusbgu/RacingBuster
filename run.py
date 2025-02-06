from app import create_app
import os

# Create the app instance
app = create_app()

# Run the app
if __name__ == '__main__':
    # Ensure that debug is set to False in production
    app.run(debug=os.environ.get('FLASK_DEBUG', False), use_reloader=False)
