# shikra/reporting/web/app.py
# Main Flask application for Shikra Analysis Framework web interface

import os
import sys
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import SelectField, TextAreaField, BooleanField, StringField
from wtforms.validators import DataRequired, Optional
from werkzeug.utils import secure_filename
import json
import uuid
from pathlib import Path

# Add the parent directories to path so we can import Shikra modules
sys.path.append(str(Path(__file__).parents[3]))

# Import Shikra modules
try:
    from shikra.reporting.modules.reporting import ReportGenerator, TimelineAnalyzer, ShikraVisualizer
    from shikra.analysis.modules.analysis import behavioral, network_analysis, memory_analysis
except ImportError as e:
    print(f"Warning: Could not import Shikra modules: {e}")
    # Continue anyway for development

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Flask app configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or 'uploads'
    MAX_CONTENT_LENGTH = 512 * 1024 * 1024  # 512MB max file size
    ANALYSIS_RESULTS_DIR = os.environ.get('ANALYSIS_RESULTS_DIR') or 'analysis_results'
    REPORTS_DIR = os.environ.get('REPORTS_DIR') or 'reports'
    ALLOWED_EXTENSIONS = {'exe', 'dll', 'doc', 'docx', 'pdf', 'zip', 'rar', '7z', 'bin', 'img', 'iso'}
    
    # Shikra-specific config
    SHIKRA_VERSION = '1.0.0'
    API_BASE_URL = '/api/v1'
    WS_BASE_URL = None  # Will be set based on request context
    
    # Analysis settings
    DEFAULT_VM_PROFILE = 'windows_7_x64'
    ANALYSIS_TIMEOUT = 1800  # 30 minutes
    
    # Database (for future use)
    DATABASE_URL = os.environ.get('DATABASE_URL') or 'sqlite:///shikra.db'

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Ensure required directories exist
for directory in [app.config['UPLOAD_FOLDER'], app.config['ANALYSIS_RESULTS_DIR'], app.config['REPORTS_DIR']]:
    os.makedirs(directory, exist_ok=True)

# Mock database (replace with real database in production)
class MockDatabase:
    def __init__(self):
        self.analyses = []
        self.users = [{'id': 1, 'username': 'admin', 'is_admin': True}]
        self._init_sample_data()
    
    def _init_sample_data(self):
        # Add some sample analyses for demo
        sample_analyses = [
            {
                'id': str(uuid.uuid4()),
                'filename': 'suspicious_sample.exe',
                'file_size': 2048576,
                'status': 'completed',
                'verdict': 'malicious',
                'score': 85,
                'created_at': datetime.now() - timedelta(hours=2),
                'completed_at': datetime.now() - timedelta(hours=1, minutes=45),
                'user_id': 1
            },
            {
                'id': str(uuid.uuid4()),
                'filename': 'document.docx',
                'file_size': 1024000,
                'status': 'running',
                'verdict': None,
                'score': None,
                'created_at': datetime.now() - timedelta(minutes=15),
                'completed_at': None,
                'user_id': 1
            },
            {
                'id': str(uuid.uuid4()),
                'filename': 'benign_tool.exe',
                'file_size': 512000,
                'status': 'completed',
                'verdict': 'benign',
                'score': 12,
                'created_at': datetime.now() - timedelta(days=1),
                'completed_at': datetime.now() - timedelta(days=1, hours=-1),
                'user_id': 1
            }
        ]
        self.analyses.extend(sample_analyses)

db = MockDatabase()

# Mock current user (replace with proper authentication in production)
class MockUser:
    def __init__(self):
        self.id = 1
        self.username = 'admin'
        self.is_admin = True

@app.context_processor
def inject_user():
    return {'current_user': MockUser()}

# Helper functions
def get_system_status():
    """Get current system status"""
    return {
        'status': 'running',
        'uptime': '2d 14h 32m',
        'cpu_usage': 45,
        'memory_usage': 62,
        'disk_usage': 78,
        'free_space': '150GB'
    }

def get_system_info():
    """Get system information"""
    return {
        'version': app.config['SHIKRA_VERSION'],
        'uptime': '2d 14h 32m',
        'cpu_usage': 45,
        'memory_usage': 62,
        'disk_usage': 78,
        'free_space': '150GB'
    }

def get_dashboard_stats():
    """Get dashboard statistics"""
    total_analyses = len(db.analyses)
    running_analyses = len([a for a in db.analyses if a['status'] == 'running'])
    completed_today = len([a for a in db.analyses if a['status'] == 'completed' and 
                          a['completed_at'] and a['completed_at'].date() == datetime.now().date()])
    failed_analyses = len([a for a in db.analyses if a['status'] == 'failed'])
    
    return {
        'total_analyses': total_analyses,
        'running_analyses': running_analyses,
        'completed_today': completed_today,
        'failed_analyses': failed_analyses
    }

def get_chart_data():
    """Generate chart data for dashboard"""
    # Mock data - replace with real analytics
    return {
        'trends': {
            'labels': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            'data': [12, 19, 8, 15, 22, 7, 14]
        },
        'verdicts': {
            'labels': ['Malicious', 'Suspicious', 'Benign', 'Unknown'],
            'data': [15, 8, 25, 5]
        }
    }

def get_threat_intel():
    """Get threat intelligence feed"""
    return {
        'last_updated': datetime.now() - timedelta(minutes=30),
        'alerts': [
            {
                'title': 'New Ransomware Campaign Detected',
                'description': 'A new ransomware family targeting healthcare organizations has been observed.',
                'severity': 'high',
                'source': 'Threat Intelligence Team',
                'published_at': datetime.now() - timedelta(hours=2)
            },
            {
                'title': 'Phishing Campaign Update',
                'description': 'Updated indicators for ongoing phishing campaign targeting financial institutions.',
                'severity': 'medium',
                'source': 'CERT Alerts',
                'published_at': datetime.now() - timedelta(hours=6)
            }
        ]
    }

# Custom template filters
@app.template_filter('timeago')
def timeago_filter(dt):
    """Convert datetime to human-readable time ago format"""
    if not dt:
        return 'N/A'
    
    now = datetime.now()
    diff = now - dt
    
    if diff.days > 0:
        return f"{diff.days}d ago"
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f"{hours}h ago"
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        return f"{minutes}m ago"
    else:
        return "Just now"

@app.template_filter('filesizeformat')
def filesizeformat_filter(size):
    """Format file size in human readable format"""
    if not size:
        return 'N/A'
    
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"

# Forms
class AnalysisSubmissionForm(FlaskForm):
    file = FileField('Malware Sample', validators=[
        FileRequired('Please select a file to analyze'),
        FileAllowed(app.config['ALLOWED_EXTENSIONS'], 'File type not allowed')
    ])
    vm_profile = SelectField('VM Profile', choices=[
        ('windows_7_x64', 'Windows 7 x64'),
        ('windows_10_x64', 'Windows 10 x64'),
        ('ubuntu_20_x64', 'Ubuntu 20.04 x64')
    ], default='windows_7_x64')
    analysis_timeout = SelectField('Analysis Timeout', choices=[
        ('300', '5 minutes'),
        ('600', '10 minutes'),
        ('1800', '30 minutes'),
        ('3600', '1 hour')
    ], default='1800')
    enable_network = BooleanField('Enable Network Analysis', default=True)
    enable_memory = BooleanField('Enable Memory Analysis', default=True)
    comments = TextAreaField('Comments', validators=[Optional()])

# Routes
@app.route('/')
def index():
    """Redirect to dashboard"""
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    """Main dashboard page"""
    recent_analyses = sorted(db.analyses, key=lambda x: x['created_at'], reverse=True)[:10]
    
    return render_template('dashboard.html',
                         recent_analyses=recent_analyses,
                         stats=get_dashboard_stats(),
                         system_status=get_system_status(),
                         system_info=get_system_info(),
                         chart_data=get_chart_data(),
                         threat_intel=get_threat_intel(),
                         is_first_visit=len(db.analyses) == 0)

@app.route('/submit', methods=['GET', 'POST'])
def submit():
    """Sample submission page"""
    form = AnalysisSubmissionForm()
    
    if form.validate_on_submit():
        # Save uploaded file
        file = form.file.data
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Create analysis record
        analysis_id = str(uuid.uuid4())
        analysis = {
            'id': analysis_id,
            'filename': filename,
            'file_size': os.path.getsize(file_path),
            'file_path': file_path,
            'status': 'submitted',
            'verdict': None,
            'score': None,
            'vm_profile': form.vm_profile.data,
            'analysis_timeout': int(form.analysis_timeout.data),
            'enable_network': form.enable_network.data,
            'enable_memory': form.enable_memory.data,
            'comments': form.comments.data,
            'created_at': datetime.now(),
            'completed_at': None,
            'user_id': 1
        }
        
        db.analyses.append(analysis)
        
        # In a real implementation, this would trigger the analysis pipeline
        logger.info(f"Analysis {analysis_id} submitted for file {filename}")
        
        flash(f'Analysis submitted successfully! Analysis ID: {analysis_id}', 'success')
        return redirect(url_for('analyses_detail', id=analysis_id))
    
    return render_template('submit.html', form=form)

@app.route('/analyses')
def analyses_list():
    """List all analyses"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Filter analyses
    status_filter = request.args.get('status', 'all')
    verdict_filter = request.args.get('verdict', 'all')
    
    filtered_analyses = db.analyses
    if status_filter != 'all':
        filtered_analyses = [a for a in filtered_analyses if a['status'] == status_filter]
    if verdict_filter != 'all':
        filtered_analyses = [a for a in filtered_analyses if a['verdict'] == verdict_filter]
    
    # Sort by creation date (newest first)
    filtered_analyses = sorted(filtered_analyses, key=lambda x: x['created_at'], reverse=True)
    
    # Pagination (simple implementation)
    total = len(filtered_analyses)
    start = (page - 1) * per_page
    end = start + per_page
    analyses = filtered_analyses[start:end]
    
    return render_template('analyses/list.html',
                         analyses=analyses,
                         total=total,
                         page=page,
                         per_page=per_page,
                         status_filter=status_filter,
                         verdict_filter=verdict_filter)

@app.route('/analyses/<id>')
def analyses_detail(id):
    """Analysis detail page"""
    analysis = next((a for a in db.analyses if a['id'] == id), None)
    if not analysis:
        flash('Analysis not found', 'error')
        return redirect(url_for('analyses_list'))
    
    # Mock analysis results
    mock_results = {
        'behavioral_analysis': {
            'classification': 'Suspicious',
            'score': 75,
            'signatures': [
                {'type': 'Persistence', 'severity': 'high', 'description': 'Creates registry run key'},
                {'type': 'Network', 'severity': 'medium', 'description': 'Connects to suspicious domain'}
            ]
        },
        'network_analysis': {
            'classification': 'Malicious C2',
            'score': 85,
            'suspicious_domains': ['evil.example.com', 'malware.badsite.net']
        },
        'memory_analysis': {
            'classification': 'Highly Suspicious',
            'score': 80,
            'injected_processes': ['notepad.exe', 'explorer.exe']
        }
    }
    
    return render_template('analyses/detail.html',
                         analysis=analysis,
                         results=mock_results)

@app.route('/analyses/<id>/progress')
def analyses_progress(id):
    """Analysis progress page"""
    analysis = next((a for a in db.analyses if a['id'] == id), None)
    if not analysis:
        flash('Analysis not found', 'error')
        return redirect(url_for('analyses_list'))
    
    # Mock progress data
    progress = {
        'overall_progress': 65,
        'current_stage': 'Behavioral Analysis',
        'stages': [
            {'name': 'File Upload', 'status': 'completed', 'progress': 100},
            {'name': 'Static Analysis', 'status': 'completed', 'progress': 100},
            {'name': 'Dynamic Analysis', 'status': 'running', 'progress': 65},
            {'name': 'Network Analysis', 'status': 'pending', 'progress': 0},
            {'name': 'Memory Analysis', 'status': 'pending', 'progress': 0},
            {'name': 'Report Generation', 'status': 'pending', 'progress': 0}
        ],
        'logs': [
            {'timestamp': datetime.now() - timedelta(minutes=5), 'level': 'info', 'message': 'Analysis started'},
            {'timestamp': datetime.now() - timedelta(minutes=3), 'level': 'info', 'message': 'VM environment initialized'},
            {'timestamp': datetime.now() - timedelta(minutes=1), 'level': 'warning', 'message': 'Suspicious behavior detected'}
        ]
    }
    
    return render_template('analyses/progress.html',
                         analysis=analysis,
                         progress=progress)

@app.route('/analyses/monitoring')
def analyses_monitoring():
    """Live monitoring page"""
    return render_template('analyses/monitoring.html')

@app.route('/search')
def search():
    """Search analyses page"""
    query = request.args.get('q', '')
    results = []
    
    if query:
        # Simple search implementation
        results = [a for a in db.analyses if 
                  query.lower() in a['filename'].lower() or 
                  (a['comments'] and query.lower() in a['comments'].lower())]
    
    return render_template('search.html', query=query, results=results)

# API Routes
@app.route('/api/v1/analyses', methods=['GET'])
def api_analyses_list():
    """API endpoint for analyses list"""
    return jsonify({
        'success': True,
        'data': db.analyses,
        'total': len(db.analyses)
    })

@app.route('/api/v1/analyses/<id>/status', methods=['GET'])
def api_analysis_status(id):
    """API endpoint for analysis status"""
    analysis = next((a for a in db.analyses if a['id'] == id), None)
    if not analysis:
        return jsonify({'success': False, 'error': 'Analysis not found'}), 404
    
    return jsonify({
        'success': True,
        'status': analysis['status'],
        'progress': 65 if analysis['status'] == 'running' else 100 if analysis['status'] == 'completed' else 0
    })

@app.route('/api/v1/analyses/<id>/cancel', methods=['POST'])
def api_cancel_analysis(id):
    """API endpoint to cancel analysis"""
    analysis = next((a for a in db.analyses if a['id'] == id), None)
    if not analysis:
        return jsonify({'success': False, 'error': 'Analysis not found'}), 404
    
    if analysis['status'] not in ['running', 'submitted']:
        return jsonify({'success': False, 'error': 'Analysis cannot be cancelled'}), 400
    
    analysis['status'] = 'cancelled'
    logger.info(f"Analysis {id} cancelled by user")
    
    return jsonify({'success': True, 'message': 'Analysis cancelled successfully'})

@app.route('/api/v1/system/status', methods=['GET'])
def api_system_status():
    """API endpoint for system status"""
    return jsonify({
        'success': True,
        'data': get_system_status()
    })

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f'Server Error: {error}')
    return render_template('errors/500.html'), 500

@app.errorhandler(413)
def too_large(error):
    flash('File too large. Maximum size is 512MB.', 'error')
    return redirect(url_for('submit'))

# Template functions
@app.template_global()
def moment():
    """Make datetime available in templates"""
    return datetime

# CLI commands (for development)
@app.cli.command()
def init_db():
    """Initialize the database with sample data"""
    click.echo('Initializing database with sample data...')
    # In a real app, this would create database tables
    db._init_sample_data()
    click.echo('Database initialized!')

@app.cli.command()
def run_analysis():
    """Run a sample analysis (for testing)"""
    click.echo('Running sample analysis...')
    # This would trigger the actual analysis pipeline
    click.echo('Analysis completed!')

# WebSocket support (basic implementation)
try:
    from flask_socketio import SocketIO, emit
    
    socketio = SocketIO(app, cors_allowed_origins="*")
    
    @socketio.on('connect')
    def handle_connect():
        logger.info('Client connected to WebSocket')
        emit('status', {'message': 'Connected to Shikra monitoring'})
    
    @socketio.on('disconnect')
    def handle_disconnect():
        logger.info('Client disconnected from WebSocket')
    
    @socketio.on('start_monitoring')
    def handle_start_monitoring(data):
        logger.info('Monitoring started via WebSocket')
        emit('monitoring_status', {'status': 'started'})
        
        # Send sample monitoring data
        emit('monitoring_update', {
            'event_type': 'activity',
            'timestamp': datetime.now().isoformat(),
            'category': 'process',
            'severity': 'info',
            'title': 'Process monitoring started',
            'description': 'Real-time process monitoring is now active'
        })
    
    @socketio.on('stop_monitoring')
    def handle_stop_monitoring(data):
        logger.info('Monitoring stopped via WebSocket')
        emit('monitoring_status', {'status': 'stopped'})
    
    # Function to send updates to connected clients
    def send_monitoring_update(data):
        if 'socketio' in globals():
            socketio.emit('monitoring_update', data)

except ImportError:
    logger.warning('Flask-SocketIO not available. WebSocket functionality disabled.')
    socketio = None

# Development server configuration
if __name__ == '__main__':
    import click
    
    # Check if we have the required dependencies
    missing_deps = []
    try:
        import flask_wtf
    except ImportError:
        missing_deps.append('Flask-WTF')
    
    if missing_deps:
        print(f"Missing dependencies: {', '.join(missing_deps)}")
        print("Install with: pip install Flask Flask-WTF Flask-SocketIO")
        sys.exit(1)
    
    # Run the application
    debug_mode = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    port = int(os.environ.get('PORT', 5000))
    
    if socketio:
        logger.info(f'Starting Shikra web interface with WebSocket support on port {port}')
        socketio.run(app, debug=debug_mode, host='0.0.0.0', port=port)
    else:
        logger.info(f'Starting Shikra web interface on port {port}')
        app.run(debug=debug_mode, host='0.0.0.0', port=port)