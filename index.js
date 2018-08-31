const saml = require("saml20"),
	UnauthorizedError = require('./errors/UnauthorizedError'),
	unless = require('express-unless'),
	async = require('async'),
	set = require('lodash.set');

/* const DEFAULT_REVOKED_FUNCTION = function (_, __, cb) { return cb(null, false); }; */

module.exports = function (options) {
	/* const isRevokedCallback = options.isRevoked || DEFAULT_REVOKED_FUNCTION; */

	options = options || {};
	const _requestProperty = options.userProperty || options.requestProperty || 'user';
	const _resultProperty = options.resultProperty;
	const credentialsRequired = typeof options.credentialsRequired === 'undefined' ? true : options.credentialsRequired;

	const middleware = function (req, res, next) {
		let token;

		if (req.method === 'OPTIONS' && req.headers.hasOwnProperty('access-control-request-headers')) {
			const hasAuthInAccessControl = !!~req.headers['access-control-request-headers']
				.split(',').map(function (header) {
					return header.trim();
				}).indexOf('authorization');

			if (hasAuthInAccessControl) {
				return next();
			}
		}

		if (options.getToken && typeof options.getToken === 'function') {
			try {
				token = options.getToken(req);
			} catch (e) {
				return next(e);
			}
		} else if (req.headers && req.headers.authorization) {
			token = req.headers.authorization;
		}

		if (!token) {
			if (credentialsRequired) {
				return next(new UnauthorizedError('credentials_required', { message: 'No authorization token was found' }));
			} else {
				return next();
			}
		}

		async.autoInject({
			token: (cb) => {
				saml.parse(Buffer.from(token, 'base64').toString("ascii"), (err, profile) => {
					if (err) {
						return cb(new UnauthorizedError('invalid_token', err));
					}
					cb(null, profile)
				});
			}
		}, function (err, scope) {
			if (err) {
				return next(err);
			}
			if (_resultProperty) {
				set(res, _resultProperty, scope);
			} else {
				set(req, _requestProperty, scope);
			}
			next();
		});
	};

	middleware.unless = unless;
	middleware.UnauthorizedError = UnauthorizedError;

	return middleware;
};

module.exports.UnauthorizedError = UnauthorizedError;