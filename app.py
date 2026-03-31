from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import numpy as np
from datetime import datetime
import os
import json
import io
import smtplib 
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vehicle_intrusion.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Mail config
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "poisonousplants2024@gmail.com"
app.config["MAIL_PASSWORD"] = "wtfghdcknihmbaog"   # better to use environment variable
app.config["MAIL_DEFAULT_SENDER"] = "pisonousplants2024@gmail.com"

# Convenience variables for SMTP (used in send_detection_email)
SMTP_SERVER = app.config["MAIL_SERVER"]
SMTP_PORT = app.config["MAIL_PORT"]
SMTP_USER = app.config["MAIL_USERNAME"]
SMTP_PASSWORD = app.config["MAIL_PASSWORD"]
DEFAULT_SENDER = app.config["MAIL_DEFAULT_SENDER"]

db = SQLAlchemy(app)
# -------- Vehicle Safety State (PREVENTION INDICATOR) --------
vehicle_state = {
    "mode": "NORMAL",     # NORMAL | SAFE_MODE | RESTRICTED
    "reason": None
}


# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class DetectionResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    speed_kmh = db.Column(db.Float, nullable=False)
    brake_usage_percent = db.Column(db.Float, nullable=False)
    throttle_position = db.Column(db.Float, nullable=False)
    engine_rpm = db.Column(db.Float, nullable=True)
    steering_angle = db.Column(db.Float, nullable=True)
    detection_result = db.Column(db.String(100), nullable=False)
    attack_type = db.Column(db.String(100), nullable=True)
    confidence = db.Column(db.Float, nullable=False)
    triggered_rules = db.Column(db.Text, nullable=True)
    user = db.relationship('User', backref=db.backref('detections', lazy=True))

# -------- Prevention Action Model (ADD-ON) --------
class PreventionAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    detection_id = db.Column(db.Integer, db.ForeignKey('detection_result.id'), nullable=False)
    action_taken = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    detection = db.relationship('DetectionResult', backref=db.backref('prevention', lazy=True))


# Enhanced Fuzzy Logic Implementation with Attack Type Detection
class VehicleIntrusionDetector:
    def __init__(self):
        self.attack_types = {
            0: "Normal",
            1: "DoS Attack",
            2: "GPS Spoofing",
            3: "Fabrication Attack",
            4: "Replay Attack",
            5: "Fuzzy Attack",
            6: "Sensor Spoofing"
        }
        self.rules = self._initialize_rules()
    
    def _initialize_rules(self):
        return [
            # DoS Attack Rules
            {
                'name': 'DoS - Zero speed with full brake',
                'condition': lambda s, b, t, r, a: s == 0 and b == 100,
                'severity': 'Likely Attack',
                'attack_type': 1,
                'description': 'Vehicle stopped with full brake application - possible DoS'
            },
            {
                'name': 'DoS - Engine RPM anomaly with zero speed',
                'condition': lambda s, b, t, r, a: s == 0 and r > 2500,
                'severity': 'Likely Attack',
                'attack_type': 1,
                'description': 'Zero speed with unusually high RPM'
            },
            {
                'name': 'DoS - Complete system freeze',
                'condition': lambda s, b, t, r, a: s == 0 and b == 0 and t == 0 and r == 0,
                'severity': 'Likely Attack',
                'attack_type': 1,
                'description': 'All systems reading zero - potential DoS attack'
            },
            # Fabrication Attack Rules
            {
                'name': 'Fabrication - Contradictory brake/throttle',
                'condition': lambda s, b, t, r, a: b > 80 and t > 80,
                'severity': 'Likely Attack',
                'attack_type': 3,
                'description': 'Simultaneous high brake and throttle - signal fabrication'
            },
            {
                'name': 'Fabrication - Impossible RPM values',
                'condition': lambda s, b, t, r, a: (s < 10 and r > 3000) or (s > 100 and r < 1000),
                'severity': 'Likely Attack',
                'attack_type': 3,
                'description': 'Engine RPM inconsistent with vehicle speed'
            },
            {
                'name': 'Fabrication - Unrealistic parameter combination',
                'condition': lambda s, b, t, r, a: s > 120 and t < 10 and b < 10,
                'severity': 'Likely Attack',
                'attack_type': 3,
                'description': 'Very high speed with minimal throttle and brake'
            },
            # Replay Attack Rules
            {
                'name': 'Replay - Repeated steering patterns',
                'condition': lambda s, b, t, r, a: abs(a) > 70 and s < 30,
                'severity': 'Suspicious',
                'attack_type': 4,
                'description': 'Extreme steering at low speed - possible replay'
            },
            {
                'name': 'Replay - Consistent throttle patterns',
                'condition': lambda s, b, t, r, a: 45 <= t <= 55 and s > 60,
                'severity': 'Suspicious',
                'attack_type': 4,
                'description': 'Unnaturally consistent throttle position'
            },
            {
                'name': 'Replay - Perfect parameter maintenance',
                'condition': lambda s, b, t, r, a: (s % 10 == 0) and (t % 10 == 0) and (b % 10 == 0),
                'severity': 'Suspicious',
                'attack_type': 4,
                'description': 'Parameters at perfect intervals - possible replay'
            },
            # Fuzzy Attack Rules
            {
                'name': 'Fuzzy - Random parameter fluctuations',
                'condition': lambda s, b, t, r, a: (0 < s < 5 and t > 50) or (s > 100 and b > 50),
                'severity': 'Likely Attack',
                'attack_type': 5,
                'description': 'Random or noisy parameter combinations'
            },
            {
                'name': 'Fuzzy - Inconsistent sensor readings',
                'condition': lambda s, b, t, r, a: (s > 80 and r < 1500) or (s < 20 and r > 3500),
                'severity': 'Likely Attack',
                'attack_type': 5,
                'description': 'Sensor readings inconsistent with physics'
            },
            {
                'name': 'Fuzzy - Erratic steering behavior',
                'condition': lambda s, b, t, r, a: abs(a) > 80 and s > 80,
                'severity': 'Likely Attack',
                'attack_type': 5,
                'description': 'Extreme steering at high speed - fuzzy attack'
            },
            # Sensor Spoofing Rules
            {
                'name': 'Sensor Spoofing - Zero values attack',
                'condition': lambda s, b, t, r, a: (s == 0 and t > 0) or (r == 0 and t > 0),
                'severity': 'Likely Attack',
                'attack_type': 6,
                'description': 'Zero speed/RPM with active throttle - sensor spoofing'
            },
            {
                'name': 'Sensor Spoofing - Steering sensor manipulation',
                'condition': lambda s, b, t, r, a: abs(a) > 85 and s > 60,
                'severity': 'Likely Attack',
                'attack_type': 6,
                'description': 'Extreme steering at high speed - steering sensor attack'
            },
            {
                'name': 'Sensor Spoofing - Brake sensor manipulation',
                'condition': lambda s, b, t, r, a: b == 100 and s > 50 and t > 50,
                'severity': 'Likely Attack',
                'attack_type': 6,
                'description': 'Full brake application while accelerating - brake sensor spoofing'
            },
            # GPS Spoofing Rules
            {
                'name': 'GPS Spoofing - Impossible location jump',
                'condition': lambda s, b, t, r, a: s < 5 and r > 2000 and t > 50,
                'severity': 'Suspicious',
                'attack_type': 2,
                'description': 'Stationary vehicle with high RPM and throttle - possible GPS spoofing'
            },
            # General Suspicious Behavior Rules
            {
                'name': 'Unrealistic driving behavior',
                'condition': lambda s, b, t, r, a: s > 80 and b > 70 and t > 70,
                'severity': 'Likely Attack',
                'attack_type': 3,
                'description': 'High speed with high brake and throttle'
            },
            {
                'name': 'Contradictory signals',
                'condition': lambda s, b, t, r, a: s < 20 and b > 70 and t > 70,
                'severity': 'Likely Attack',
                'attack_type': 3,
                'description': 'Low speed with high brake and throttle'
            },
            {
                'name': 'Emergency braking scenario',
                'condition': lambda s, b, t, r, a: b > 70 and s > 60,
                'severity': 'Suspicious',
                'attack_type': None,
                'description': 'High brake at high speed - could be emergency or attack'
            },
            {
                'name': 'Coasting at high speed',
                'condition': lambda s, b, t, r, a: s > 80 and b < 20 and t < 20,
                'severity': 'Suspicious',
                'attack_type': None,
                'description': 'High speed with low brake and throttle'
            }
        ]
    
    def fuzzy_membership(self, value, low, medium, high):
        if value <= low:
            return {'low': 1.0, 'medium': 0.0, 'high': 0.0}
        elif value >= high:
            return {'low': 0.0, 'medium': 0.0, 'high': 1.0}
        elif value <= medium:
            low_degree = (medium - value) / (medium - low)
            medium_degree = (value - low) / (medium - low)
            return {'low': low_degree, 'medium': medium_degree, 'high': 0.0}
        else:
            medium_degree = (high - value) / (high - medium)
            high_degree = (value - medium) / (high - medium)
            return {'low': 0.0, 'medium': medium_degree, 'high': high_degree}
    
    def detect_attack_type(self, speed, brake, throttle, engine_rpm=None, steering_angle=None):
        engine_rpm = engine_rpm or 0
        steering_angle = steering_angle or 0
        
        speed_low = 0
        speed_medium = 40
        speed_high = 80
        
        brake_low = 0
        brake_medium = 30
        brake_high = 70
        
        throttle_low = 0
        throttle_medium = 30
        throttle_high = 70
        
        rpm_low = 0
        rpm_medium = 2000
        rpm_high = 3500
        
        speed_fuzzy = self.fuzzy_membership(speed, speed_low, speed_medium, speed_high)
        brake_fuzzy = self.fuzzy_membership(brake, brake_low, brake_medium, brake_high)
        throttle_fuzzy = self.fuzzy_membership(throttle, throttle_low, throttle_medium, throttle_high)
        rpm_fuzzy = self.fuzzy_membership(engine_rpm, rpm_low, rpm_medium, rpm_high)
        
        triggered_rules = []
        attack_scores = {attack_id: 0.0 for attack_id in self.attack_types.keys() if attack_id != 0}
        
        for rule in self.rules:
            if rule['condition'](speed, brake, throttle, engine_rpm, steering_angle):
                confidence = 0.7  # Base confidence
                if 'High' in rule['name']:
                    if 'speed' in rule['name'].lower():
                        confidence *= speed_fuzzy['high']
                    if 'brake' in rule['name'].lower():
                        confidence *= brake_fuzzy['high']
                    if 'throttle' in rule['name'].lower():
                        confidence *= throttle_fuzzy['high']
                    if 'rpm' in rule['name'].lower():
                        confidence *= rpm_fuzzy['high']
                
                confidence = max(0.3, min(0.95, confidence))
                
                triggered_rule = {
                    'rule': rule['name'],
                    'severity': rule['severity'],
                    'description': rule['description'],
                    'confidence': confidence,
                    'attack_type': rule['attack_type']
                }
                triggered_rules.append(triggered_rule)
                
                if rule['attack_type']:
                    attack_scores[rule['attack_type']] += confidence
        
        if not triggered_rules:
            return {
                'result': 'Normal',
                'attack_type': 0,
                'attack_type_label': 'Normal',
                'confidence': 0.9,
                'triggered_rules': []
            }
        
        if attack_scores:
            most_likely_attack = max(attack_scores.items(), key=lambda x: x[1])
            if most_likely_attack[1] > 0.5:
                attack_type_id = most_likely_attack[0]
                attack_type_label = self.attack_types[attack_type_id]
                attack_rules = [r for r in triggered_rules if r['attack_type'] == attack_type_id]
                overall_confidence = sum(r['confidence'] for r in attack_rules) / len(attack_rules)
            else:
                attack_type_id = None
                attack_type_label = "Suspicious Activity"
                overall_confidence = 0.6
        else:
            attack_type_id = None
            attack_type_label = "Suspicious Activity"
            overall_confidence = 0.6
        
        if attack_type_id and attack_type_id != 0:
            overall_result = 'Attack Detected'
        elif attack_type_label == "Suspicious Activity":
            overall_result = 'Suspicious Activity'
        else:
            overall_result = 'Normal'
        
        return {
            'result': overall_result,
            'attack_type': attack_type_id,
            'attack_type_label': attack_type_label,
            'confidence': min(0.95, overall_confidence),
            'triggered_rules': triggered_rules
        }
# -------- Prevention Engine (ADD-ON) --------
class VehicleAttackPreventionSystem:
    def decide_prevention(self, detection_result, attack_type):
        global vehicle_state

        if detection_result == "Attack Detected":
            vehicle_state["mode"] = "SAFE_MODE"
            vehicle_state["reason"] = attack_type
            return self._attack_prevention(attack_type)

        elif detection_result == "Suspicious Activity":
            vehicle_state["mode"] = "RESTRICTED"
            vehicle_state["reason"] = "Suspicious behavior"
            return "Restricted vehicle operation and monitoring enabled"

        else:
            vehicle_state["mode"] = "NORMAL"
            vehicle_state["reason"] = None
            return "No action required"

    def _attack_prevention(self, attack_type):
        prevention_map = {
            "DoS Attack": "Communication isolated, vehicle switched to safe mode",
            "GPS Spoofing": "GPS disabled, inertial navigation activated",
            "Fabrication Attack": "Forged data discarded, ECU values reset",
            "Replay Attack": "Cached signals invalidated",
            "Fuzzy Attack": "Signal smoothing and thresholds tightened",
            "Sensor Spoofing": "Compromised sensor isolated"
        }
        return prevention_map.get(attack_type, "Emergency vehicle halt initiated")


    def _attack_prevention(self, attack_type):
        prevention_map = {
            "DoS Attack": "Isolate communication module and switch to safe mode",
            "GPS Spoofing": "Disable GPS input and rely on inertial sensors",
            "Fabrication Attack": "Discard forged signals and reset ECU values",
            "Replay Attack": "Invalidate cached data and refresh control signals",
            "Fuzzy Attack": "Apply signal smoothing and tighten threshold limits",
            "Sensor Spoofing": "Cross-verify sensors and ignore compromised sensor"
        }
        return prevention_map.get(attack_type, "Emergency vehicle halt and alert authority")

# Initialize detector
detector = VehicleIntrusionDetector()

prevention_system = VehicleAttackPreventionSystem()


# ---------- PDF & Email Helpers ----------

def create_detection_report_pdf(detection: DetectionResult) -> bytes:
    """Generate a simple PDF report for a detection and return raw bytes."""
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    y = height - 50
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, y, "Vehicle Intrusion Detection Report")
    y -= 30

    pdf.setFont("Helvetica", 10)
    pdf.drawString(50, y, f"Report ID: {detection.id}")
    y -= 15
    pdf.drawString(50, y, f"User ID: {detection.user_id}")
    y -= 15
    pdf.drawString(50, y, f"Timestamp: {detection.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 25

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, y, "Input Parameters")
    y -= 20
    pdf.setFont("Helvetica", 10)
    pdf.drawString(60, y, f"Speed: {detection.speed_kmh} km/h")
    y -= 15
    pdf.drawString(60, y, f"Brake Usage: {detection.brake_usage_percent}%")
    y -= 15
    pdf.drawString(60, y, f"Throttle Position: {detection.throttle_position}%")
    y -= 15
    pdf.drawString(60, y, f"Engine RPM: {detection.engine_rpm if detection.engine_rpm is not None else 'N/A'}")
    y -= 15
    pdf.drawString(60, y, f"Steering Angle: {detection.steering_angle if detection.steering_angle is not None else 'N/A'}")
    y -= 25

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, y, "Detection Summary")
    y -= 20
    pdf.setFont("Helvetica", 10)
    pdf.drawString(60, y, f"Result: {detection.detection_result}")
    y -= 15
    pdf.drawString(60, y, f"Attack Type: {detection.attack_type or 'Normal'}")
    y -= 15
    pdf.drawString(60, y, f"Confidence: {round(detection.confidence * 100, 1)}%")
    y -= 25

    # Triggered rules
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, y, "Triggered Rules")
    y -= 20
    pdf.setFont("Helvetica", 9)

    try:
        rules = json.loads(detection.triggered_rules) if detection.triggered_rules else []
    except Exception:
        rules = []

    if rules:
        for rule in rules:
            if y < 80:
                pdf.showPage()
                y = height - 50
                pdf.setFont("Helvetica-Bold", 12)
                pdf.drawString(50, y, "Triggered Rules (contd.)")
                y -= 20
                pdf.setFont("Helvetica", 9)

            pdf.drawString(60, y, f"- {rule.get('rule', 'Rule')}")
            y -= 12
            desc = rule.get('description', '')
            pdf.drawString(70, y, f"{desc}")
            y -= 12
            sev = rule.get('severity', 'Unknown')
            conf = rule.get('confidence', 0.0)
            pdf.drawString(70, y, f"Severity: {sev} | Confidence: {round(conf * 100)}%")
            y -= 16
    else:
        pdf.drawString(60, y, "No suspicious rules triggered.")
        y -= 16

    pdf.showPage()
    pdf.save()
    buffer.seek(0)
    return buffer.getvalue()

def send_detection_email(user: User, detection: DetectionResult, pdf_bytes: bytes) -> bool:
    """Send an email with the detection report PDF attached to the logged-in user."""
    if not SMTP_USER or not SMTP_PASSWORD:
        print("SMTP credentials not configured.")
        return False

    try:
        msg = MIMEMultipart()
        msg['From'] = DEFAULT_SENDER or SMTP_USER
        msg['To'] = user.email
        msg['Subject'] = f"Vehicle Intrusion Detection Report #{detection.id}"

        body = f"""Hello {user.username},

Your recent vehicle intrusion detection result is:

Result: {detection.detection_result}
Attack Type: {detection.attack_type or 'Normal'}
Confidence: {round(detection.confidence * 100, 1)}%

A detailed PDF report is attached.

Regards,
Vehicle Intrusion Detection System
"""
        msg.attach(MIMEText(body, 'plain'))

        attachment = MIMEApplication(pdf_bytes, _subtype='pdf')
        attachment.add_header(
            'Content-Disposition',
            'attachment',
            filename=f"detection_report_{detection.id}.pdf"
        )
        msg.attach(attachment)

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)

        return True
    except Exception as e:
        print("Error sending email:", e)
        return False

# ---------- Routes ----------

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'error')
            return render_template('register.html')
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    recent_detections = DetectionResult.query.filter_by(
        user_id=session['user_id']
    ).order_by(DetectionResult.timestamp.desc()).limit(10).all()

    total_detections = DetectionResult.query.filter_by(
        user_id=session['user_id']
    ).count()

    attack_detections = DetectionResult.query.filter(
        DetectionResult.user_id == session['user_id'],
        DetectionResult.detection_result == 'Attack Detected'
    ).count()

    suspicious_detections = DetectionResult.query.filter(
        DetectionResult.user_id == session['user_id'],
        DetectionResult.detection_result == 'Suspicious Activity'
    ).count()

    normal_detections = DetectionResult.query.filter(
        DetectionResult.user_id == session['user_id'],
        DetectionResult.detection_result == 'Normal'
    ).count()

    attack_types_data = db.session.query(
        DetectionResult.attack_type,
        db.func.count(DetectionResult.id)
    ).filter(
        DetectionResult.user_id == session['user_id'],
        DetectionResult.attack_type != 'Normal'
    ).group_by(DetectionResult.attack_type).all()

    return render_template(
        'dashboard.html',
        username=session['username'],
        detections=recent_detections,
        total_detections=total_detections,
        attack_detections=attack_detections,
        suspicious_detections=suspicious_detections,
        normal_detections=normal_detections,
        attack_types_data=attack_types_data,
        detector=detector,
        vehicle_state=vehicle_state
    )



@app.route('/detect', methods=['GET', 'POST'])
def detect():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # ===== STEP 4: SAFE MODE ENFORCEMENT (ADD HERE) =====
    if vehicle_state["mode"] == "SAFE_MODE":
        flash("Vehicle is in SAFE MODE. Control inputs are restricted!", "error")
        return render_template(
            'detection_result.html',
            result={
                'result': 'PREVENTION ACTIVE',
                'attack_type_label': vehicle_state["reason"],
                'confidence': 1.0,
                'triggered_rules': []
            },
            input_data={},
            detector=detector,
            detection_id=None
        )
    # ===== END OF STEP 4 =====
    
    if request.method == 'POST':
        try:
            speed = float(request.form['speed'])
            brake = float(request.form['brake'])
            throttle = float(request.form['throttle'])
            engine_rpm = request.form.get('engine_rpm')
            steering_angle = request.form.get('steering_angle')
            
            engine_rpm = float(engine_rpm) if engine_rpm else None
            steering_angle = float(steering_angle) if steering_angle else None
            
            result = detector.detect_attack_type(speed, brake, throttle, engine_rpm, steering_angle)
            
            detection = DetectionResult(
                user_id=session['user_id'],
                speed_kmh=speed,
                brake_usage_percent=brake,
                throttle_position=throttle,
                engine_rpm=engine_rpm,
                steering_angle=steering_angle,
                detection_result=result['result'],
                attack_type=result['attack_type_label'],
                confidence=result['confidence'],
                triggered_rules=json.dumps(result['triggered_rules'])
            )
            db.session.add(detection)
            db.session.commit()

            # -------- Prevention Logic Execution (ADD-ON) --------
            prevention_action_text = prevention_system.decide_prevention(
                detection.detection_result,
                detection.attack_type
            )

            prevention_action = PreventionAction(
                detection_id=detection.id,
                action_taken=prevention_action_text
            )

            db.session.add(prevention_action)
            db.session.commit()

            
            return render_template(
                'detection_result.html',
                result=result,
                input_data={
                    'speed': speed,
                    'brake': brake,
                    'throttle': throttle,
                    'engine_rpm': engine_rpm,
                    'steering_angle': steering_angle
                },
                detector=detector,
                detection_id=detection.id
            )
            
        except ValueError:
            flash('Please enter valid numeric values!', 'error')
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')
    
    return render_template('detect.html', detector=detector)

@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    detections = DetectionResult.query.filter_by(
        user_id=session['user_id']
    ).order_by(DetectionResult.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('history.html', detections=detections)

@app.route('/attack_types')
def attack_types():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('attack_types.html', attack_types=detector.attack_types, detector=detector)

@app.route('/analysis')
def analysis():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    results_by_type = db.session.query(
        DetectionResult.detection_result,
        db.func.count(DetectionResult.id)
    ).filter(
        DetectionResult.user_id == session['user_id']
    ).group_by(DetectionResult.detection_result).all()
    
    attacks_by_type = db.session.query(
        DetectionResult.attack_type,
        db.func.count(DetectionResult.id)
    ).filter(
        DetectionResult.user_id == session['user_id'],
        DetectionResult.attack_type != 'Normal'
    ).group_by(DetectionResult.attack_type).all()
    
    return render_template('analysis.html',
                         results_by_type=results_by_type,
                         attacks_by_type=attacks_by_type,
                         detector=detector)

# -------- New Routes for PDF & Email --------

@app.route('/detection/<int:detection_id>/report.pdf')
def download_report(detection_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    detection = DetectionResult.query.get_or_404(detection_id)
    if detection.user_id != session['user_id']:
        abort(403)
    
    pdf_bytes = create_detection_report_pdf(detection)
    return send_file(
        io.BytesIO(pdf_bytes),
        as_attachment=True,
        download_name=f"detection_report_{detection.id}.pdf",
        mimetype='application/pdf'
    )

@app.route('/detection/<int:detection_id>/email')
def send_report_email(detection_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    detection = DetectionResult.query.get_or_404(detection_id)
    if detection.user_id != session['user_id']:
        abort(403)
    
    user = User.query.get_or_404(detection.user_id)
    pdf_bytes = create_detection_report_pdf(detection)
    success = send_detection_email(user, detection, pdf_bytes)
    
    if success:
        flash('Detection report emailed successfully!', 'success')
    else:
        flash('Failed to send email. Please check email configuration.', 'error')
    
    # Redirecting to history; you can change this to dashboard if you prefer
    return redirect(url_for('history'))

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)

                