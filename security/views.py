from flask import Blueprint, render_template
from flask_login import login_required, current_user

from config import role_required, logger

security_bp = Blueprint('security', __name__, template_folder='templates')

@security_bp.route('/security')
@login_required
@role_required('sec_admin')
def security():
    with open('securityLog.log',"r") as file:
        logs = file.readlines()[:10]

    #logger.warning(msg='[User:{}, Role:{}, IP ADdress:{}] Has accessed the security page.'.format(current_user.email,current_user.role,current_user.log.latestIP))
    return render_template('security/security.html',logs = logs)
