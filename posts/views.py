import flask_login
from flask import Blueprint, render_template, flash, url_for, redirect
from flask_login import login_user, login_required
from sqlalchemy.sql.functions import current_user
from unicodedata import category

from config import db, Post, login_manager, User, role_required, logger
from posts.forms import PostForm
from sqlalchemy import desc

posts_bp = Blueprint('posts', __name__, template_folder='templates')

@posts_bp.route('/create', methods=('GET', 'POST'))
@login_required
@role_required('end_user')
def create():
    form = PostForm()
    if form.validate_on_submit():
        new_post = Post(user_id=flask_login.current_user.id ,title=form.title.data, body=form.body.data)
        db.session.add(new_post)
        db.session.commit()
        flash('Post created', category='success')
        logger.warning(msg='[User:{},IP Address: {}] Successfully created a post {}.'.format(current_user.email,current_user.log.latestIP,current_user.posts.title))
        return redirect(url_for('posts.posts'))

    return render_template('posts/create.html', form=form)

@posts_bp.route('/posts')
@login_required
@role_required('end_user')
def posts():
    all_posts = Post.query.order_by(desc('id')).all()
    return render_template('posts/posts.html', posts=all_posts)

@posts_bp.route('/<int:id>/update', methods=('GET', 'POST'))
@login_required
@role_required('end_user')
def update(id):

    post_to_update = Post.query.filter_by(id=id).first()

    if post_to_update.userid != flask_login.current_user.id:
        flash('You cannot edit other people posts', category='danger')
        logger.warning(msg = '[User:{}] Tried to edit post they dont have permissions to do so.'.format(current_user.email))
        return redirect(url_for('posts.posts'))

    if not post_to_update:
        return redirect(url_for('posts.posts'))

    form = PostForm()

    if form.validate_on_submit():
        post_to_update.update(title=form.title.data, body=form.body.data)

        flash('Post updated', category='success')
        return redirect(url_for('posts.posts'))

    form.title.data = post_to_update.title
    form.body.data = post_to_update.body

    return render_template('posts/update.html', form=form)

@posts_bp.route('/<int:id>/delete')
@login_required
@role_required('end_user')
def delete(id):
    post = Post.query.filter_by(id=id).first()
    if post.userid != flask_login.current_user.id:
        flash('You cannot delete another persons post.',category='danger')
        logger.warning(msg='[User:{}] Tried to delete a post that they dont have permissions to do so.'.format(current_user.email))
        return redirect(url_for('posts.posts'))
    else:
        post.delete()
        db.session.commit()
        flash('Post deleted', category='success')
        return redirect(url_for('posts.posts'))