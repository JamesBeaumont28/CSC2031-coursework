import flask_login
from flask import Blueprint, render_template, flash, url_for, redirect
from flask_login import login_user, login_required
from sqlalchemy.sql.functions import current_user
from unicodedata import category

from config import db, Post, login_manager, User
from posts.forms import PostForm
from sqlalchemy import desc

posts_bp = Blueprint('posts', __name__, template_folder='templates')

@posts_bp.route('/create', methods=('GET', 'POST'))
#@login_required
def create():
    form = PostForm()
    user = User.query.filter(User.email == "jamesbeaumont28@gmail.com").first()
    login_user(user)
    if form.validate_on_submit():
        new_post = Post(user_id=flask_login.current_user.id ,title=form.title.data, body=form.body.data)
        db.session.add(new_post)
        db.session.commit()
        flash('Post created', category='success')
        return redirect(url_for('posts.posts'))

    return render_template('posts/create.html', form=form)

@posts_bp.route('/posts')
#@login_required
def posts():
    all_posts = Post.query.order_by(desc('id')).all()
    return render_template('posts/posts.html', posts=all_posts)

@posts_bp.route('/<int:id>/update', methods=('GET', 'POST'))
#@login_required
def update(id):

    post_to_update = Post.query.filter_by(id=id).first()

    if post_to_update.userid != flask_login.current_user.id:
        flash('You cannot edit other people posts', category='danger')
        return redirect(url_for('accounts.login'))

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
#@login_required
def delete(id):
    post = Post.query.filter_by(id=id).first()
    if post.user_id != flask_login.current_user.id:
        flash('You cannot delete another persons post.',category='danger')
        return redirect('posts.posts')
    else:
        post.delete()
        db.session.commit()
        flash('Post deleted', category='success')
        return redirect(url_for('posts.posts'))