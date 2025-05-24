from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, DecimalField, RadioField, TextAreaField, DateField, FloatField, HiddenField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Regexp, NumberRange, Optional
from models import User
import re

def strong_password(form, field):
    password = field.data
    if len(password) < 8:
        raise ValidationError('Password must be at least 8 characters long.')
    if not re.search(r'[A-Z]', password):
        raise ValidationError('Password must contain at least one uppercase letter.')
    if not re.search(r'[a-z]', password):
        raise ValidationError('Password must contain at least one lowercase letter.')
    if not re.search(r'\d', password):
        raise ValidationError('Password must contain at least one digit.')
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValidationError('Password must contain at least one special character.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Keep me logged in')
    submit = SubmitField('Login')

    def validate(self, extra_validators=None):
        return super(LoginForm, self).validate()

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        strong_password,
        EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Confirm Password')  # <-- Change label here
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

    def validate(self, extra_validators=None):
        return super(RegistrationForm, self).validate()

class TransferForm(FlaskForm):
    transfer_type = RadioField('Transfer Type', 
                              choices=[('username', 'By Username'), ('account', 'By Account Number')],
                              default='username')
    recipient_username = StringField('Recipient Username', validators=[Optional()])
    recipient_account = StringField('Recipient Account Number', validators=[Optional()])
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=0.01, message="Amount must be greater than 0")])
    submit = SubmitField('Transfer')

    def validate(self, extra_validators=None):
        if not super(TransferForm, self).validate():
            return False
            
        if self.transfer_type.data == 'username' and not self.recipient_username.data:
            self.recipient_username.errors = ['Username is required when transferring by username']
            return False
            
        if self.transfer_type.data == 'account' and not self.recipient_account.data:
            self.recipient_account.errors = ['Account number is required when transferring by account number']
            return False
            
        # Check that at least one of the recipient fields has data
        if not self.recipient_username.data and not self.recipient_account.data:
            self.recipient_username.errors = ['Either username or account number must be provided']
            return False
            
        # Validate recipient exists
        user = None
        if self.transfer_type.data == 'username' and self.recipient_username.data:
            user = User.query.filter_by(username=self.recipient_username.data).first()
            if not user:
                self.recipient_username.errors = ['No user with that username']
                return False
        elif self.transfer_type.data == 'account' and self.recipient_account.data:
            user = User.query.filter_by(account_number=self.recipient_account.data).first()
            if not user:
                self.recipient_account.errors = ['No account with that number']
                return False
                
        return True

class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate(self, extra_validators=None):
        return super(ResetPasswordRequestForm, self).validate()

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), strong_password])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

    def validate(self, extra_validators=None):
        return super(ResetPasswordForm, self).validate()

class DepositForm(FlaskForm):
    account_number = StringField('Account Number', validators=[DataRequired()])
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=0.01, message="Amount must be greater than 0")])
    submit = SubmitField('Deposit')
    
    def validate(self, extra_validators=None):
        if not super(DepositForm, self).validate():
            return False
            
        # Validate account exists
        user = User.query.filter_by(account_number=self.account_number.data).first()
        if not user:
            self.account_number.errors = ['No account with that number']
            return False
            
        return True

class UserEditForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    firstname = StringField('First Name', validators=[Optional()])
    lastname = StringField('Last Name', validators=[Optional()])
    
    # Detailed address fields
    address_line = StringField('Street Address', validators=[Optional()])
    postal_code = StringField('Postal Code', validators=[Optional()])
    
    # Hidden fields to store codes
    region_code = HiddenField('Region Code')
    province_code = HiddenField('Province Code')
    city_code = HiddenField('City Code')
    barangay_code = HiddenField('Barangay Code')
    
    # Display fields
    region_name = SelectField('Region', choices=[], validators=[Optional()])
    province_name = SelectField('Province', choices=[], validators=[Optional()])
    city_name = SelectField('City/Municipality', choices=[], validators=[Optional()])
    barangay_name = SelectField('Barangay', choices=[], validators=[Optional()])
    
    phone = StringField('Phone Number', validators=[Optional()])
    
    # Add status field for admins to change user status
    status = SelectField('Account Status', 
                        choices=[('active', 'Active'), 
                                ('deactivated', 'Deactivated'), 
                                ('pending', 'Pending')],
                        validators=[DataRequired()])
    
    submit = SubmitField('Update User')
    
    def __init__(self, original_email, *args, **kwargs):
        super(UserEditForm, self).__init__(*args, **kwargs)
        self.original_email = original_email
        
    def validate_email(self, email):
        if email.data != self.original_email:
            user = User.query.filter_by(email=email.data).first()
            if user is not None:
                raise ValidationError('This email is already in use. Please use a different email address.')
    
    def validate(self, extra_validators=None):
        return super(UserEditForm, self).validate()

class ConfirmTransferForm(FlaskForm):
    recipient_username = HiddenField('Recipient Username')
    recipient_account = HiddenField('Recipient Account Number')
    amount = HiddenField('Amount')
    transfer_type = HiddenField('Transfer Type')
    submit = SubmitField('Confirm Transfer')

class ProfileForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=100)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=100)])
    phone_number = StringField('Phone Number', validators=[DataRequired(), Length(max=20)])
    address = TextAreaField('Address', validators=[DataRequired(), Length(max=200)])
    date_of_birth = DateField('Date of Birth', validators=[DataRequired()], format='%Y-%m-%d')
    submit = SubmitField('Complete Profile')

class SetupPINForm(FlaskForm):
    pin = PasswordField('6-Digit PIN', validators=[
        DataRequired(),
        Length(min=6, max=6, message="PIN must be exactly 6 digits"),
        Regexp('^[0-9]*$', message="PIN must contain only digits")
    ])
    confirm_pin = PasswordField('Confirm PIN', validators=[
        DataRequired(),
        EqualTo('pin', message='PINs must match')
    ])
    submit = SubmitField('Set PIN')

class VerifyPINForm(FlaskForm):
    pin = PasswordField('Enter your 6-Digit PIN', validators=[
        DataRequired(),
        Length(min=6, max=6, message="PIN must be exactly 6 digits"),
        Regexp('^[0-9]*$', message="PIN must contain only digits")
    ])
    submit = SubmitField('Verify')

class ChangePINForm(FlaskForm):
    current_pin = PasswordField('Current PIN', validators=[
        DataRequired(),
        Length(min=6, max=6, message="PIN must be exactly 6 digits")
    ])
    new_pin = PasswordField('New 6-Digit PIN', validators=[
        DataRequired(),
        Length(min=6, max=6, message="PIN must be exactly 6 digits"),
        Regexp('^[0-9]*$', message="PIN must contain only digits")
    ])
    confirm_new_pin = PasswordField('Confirm New PIN', validators=[
        DataRequired(),
        EqualTo('new_pin', message='PINs must match')
    ])
    submit = SubmitField('Change PIN')
