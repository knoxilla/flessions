# Box SDK and Oauth2 in Flask

Just a quick demo of authorizing the Box SDK via OauthW in a Flask app.

Fake user logins are associated with sessions, and Flask-Sessions is used to store session keys/values in local Redis at 127.0.0.1:6379.

To run, clone this repo, `cd` into it, and:

	% virtualenv env
	% . env/bin/activate
	% pip install -r requirements.txt
	% cp boxapp.cfg-sample boxapp.cfg
	% <edit boxapp.cfg to add your client_id and client_secret>
	% python flessions.py

The `/auth/` route kicks off the Oauth2 journey, and the `/callback` route completes the circle.

Once the access_token and refresh_token are stored in the session, we can pull them out to construct an authenticated Box client on-demand.

The `/whoami` and `/mystuff` routes exercise the Box API after the application has been authorized, and the tokens stored.

Lots to do here to make this sane regarding users, sessions, expiry, persistence, etc.
