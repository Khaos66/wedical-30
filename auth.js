const debug = require('debug')('wedical:auth');
const session = require('express-session');
const NedbStore = require('nedb-session-store')(session);
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const i18n = require('i18n');
const Authorization = require('node-authorization').Authorization;
const compileProfile = require('node-authorization').profileCompiler;
const config = require('./config');
const {
    Strategies
} = require('./auth-utils');
var User = require('./models/user');
var Role = require('./models/role');

/**
 * Handles all the complicated authentication stuff
 *
 * @class Auth
 */
class Auth {

    /**
     * Asserts that the current user is authorized to access a resources.
     * Aborts the request with 403 status if not authorized
     * @param {string} objName Name of the object to access
     * @param {Object} objFields Authorization relevant fields and values of the object
     */
    static authorize(objName, objFields) {
        return function (req, res, next) {
            if (!req.user.Authorization || !req.user.Authorization.check(objName, objFields)) {
                // Send HTTP FORBIDDEN
                return res.status(403).send('Access Forbidden');
            }
            next();
        };
    }

    /**
     * Merges all auth profiles of a users roles and compiles the profile for authorization
     * @param {User} user The user whos auth profile to complie
     */
    static async compileAuthorization(user) {
        user.roles = user.roles ? user.roles : [];
        let userProfiles = [];
        // Merge all profiles from rules
        for (let roleId of user.roles) {
            await Role.findOne({
                    _id: roleId
                })
                .then(function (role, err) {
                    if (role) {
                        userProfiles.push(role.auth);
                    }
                });
        }
        // compile profile
        user.authProfile = compileProfile(userProfiles);
    }

    /**
     * Grants a user a new privilegue
     * @param {Role} role The role whos privilegues to edit
     * @param {string} authObject The name of the authorization object to add
     * @param {Object} authFields The fields and values of the authorization object to add
     */
    static grant(role, authObject, authFields) {
        role.auth = Auth.grantToProfile(role.auth ? role.auth : [], authObject, authFields);
    }

    /**
     * Adds a new authorization entry to a authorization profile array
     * @param {Array} authArr A array with all other authoriizations
     * @param {string} authObject The name of the authorization object to add
     * @param {Object} authFields The fields and values of the authorization object to add
     * @returns Array with new authorization profile
     */
    static grantToProfile(authArr, authObject, authFields) {
        authArr = authArr ? authArr : [];
        if (!authObject) {
            return authArr;
        }
        authFields = authFields ? authFields : {};

        // check if object is already granted
        let obj = authArr.find(x => x.AuthObject === authObject);
        if (obj) {
            // same auth obj found
            let objAuthFields = obj.AuthFieldValue;

            // check if the fields are also already knwon
            for (let [key, values] of Object.entries(authFields)) {
                if (objAuthFields[key]) {
                    let objValues = objAuthFields[key];
                    // field is known
                    for (let value of values) {
                        if (!objValues.find(x => x == value)) {
                            objValues.push(value);
                        }
                    }
                } else {
                    // field is unkown
                    objAuthFields[key] = values;
                }
            }
        } else {
            // is new auth obj
            authArr.push({
                "AuthObject": authObject,
                "AuthFieldValue": authFields,
            });
        }
        return authArr;
    }

    /**
     * Ensures that the user is authenticated (logged in)
     * @param {string} url Redirect URL after login
     */
    static authenticate(url) {
        return [
            // passport.js SessionStrategy accepts empty sessions as valid!? WTF!
            passport.authenticate('session'),
            // Therefore we do the failure redirect on our own here
            function (req, res, next) {
                if (!req.user) {
                    if (!url) {
                        // Send HTTP FORBIDDEN
                        return res.status(403).send('Access Forbidden');
                    }
                    return res.redirect('/login?redirect_url=' + encodeURIComponent(url));
                }
                next();
            }
        ];
    }

    /**
     * Configurates authentication middleware
     * @param {Object} app - express app instance
     */
    static useAuthentication(app) {
        // local username / password
        passport.use(new LocalStrategy({
                usernameField: 'email',
                passwordField: 'password'
            },
            function (username, password, done) {
                username = username.toLowerCase();
                debug(`Local user: ${username} pw(len):${password.length}`);
                User.findOne({
                    email: username,
                    strategy: Strategies.LOCAL
                }).then(async function (user, err) {
                    if (err) {
                        debug(`Error: ${JSON.stringify(err)}`);
                        return done(err);
                    }
                    if (!user) {
                        debug('ERROR: User unknown!');
                        return done(null, false, {
                            param: 'email',
                            msg: i18n.__('Incorrect email or password.')
                        });
                    }
                    if (!user.validatePassword(password)) {
                        debug('ERROR: Invalid password!');
                        return done(null, false, {
                            param: 'password',
                            msg: i18n.__('Incorrect email or password.')
                        });
                    }

                    // Aquire auth profile from user roles
                    await Auth.compileAuthorization(user);

                    debug(`User successsfuly logged-in: ${username}`);
                    done(null, user);
                });
            }));

        // google authentication
        if (config.authProviders &&
            config.authProviders.google &&
            config.authProviders.google.clientID) {
            passport.use(new GoogleStrategy({
                    clientID: config.authProviders.google.clientID,
                    clientSecret: config.authProviders.google.clientSecret,
                    callbackURL: `${config.baseUrl}auth2/google/callback`
                },
                function (accessToken, refreshToken, profile, done) {
                    User.findOne({
                        googleId: profile.id
                    }).then(async function (user, err) {
                        if (err) {
                            debug(`Error: ${JSON.stringify(err)}`);
                            return done(err);
                        }
                        if (!user) {
                            debug('ERROR: User unknown!');
                            return done(null, null, profile);
                        }

                        // Aquire auth profile from user roles
                        await Auth.compileAuthorization(user);

                        debug(`User successsfuly logged-in: ${user.name}`);
                        done(null, user);
                    });
                }
            ));
        }

        // facebook
        if (config.authProviders &&
            config.authProviders.facebook &&
            config.authProviders.facebook.appID) {
            passport.use(new FacebookStrategy({
                    clientID: config.authProviders.facebook.appID,
                    clientSecret: config.authProviders.facebook.appSecret,
                    callbackURL: `${config.baseUrl}auth2/facebook/callback`,
                    profileFields: ['id', 'emails', 'name', 'picture.type(large)']
                },
                function (accessToken, refreshToken, profile, done) {
                    User.findOne({
                        facebookId: profile.id
                    }).then(async function (user, err) {
                        if (err) {
                            debug(`Error: ${JSON.stringify(err)}`);
                            return done(err);
                        }
                        if (!user) {
                            debug('ERROR: User unknown!');
                            return done(null, null, profile);
                        }

                        // Aquire auth profile from user roles
                        await Auth.compileAuthorization(user);

                        debug(`User successsfuly logged-in: ${user.name}`);
                        done(null, user);
                    });
                }
            ));
        }

        // user session serialization
        passport.serializeUser(function (user, done) {
            debug(`Serialize user: ${user._id}`);
            done(null, {
                userid: user._id,
                authProfile: user.authProfile
            });
        });

        passport.deserializeUser(function (identity, done) {
            debug(`Deserialize user: ${identity.userid}`);
            User.findOne({
                    _id: identity.userid
                })
                .then(function (user) {
                    debug('user found');

                    const reqUser = {
                        identity: user,
                        Authorization: null,
                    };

                    // load authentication profile
                    if (identity.userid && identity.authProfile) {
                        reqUser.Authorization = new Authorization(identity.userid, identity.authProfile);
                    }

                    done(null, reqUser);
                })
                .catch(function (err) {
                    debug(`ERROR: ${err}`);
                    done(err);
                });
        });

        // auth middleware
        app.use(passport.initialize());
        app.use(passport.session());
    }

    /**
     * Creates the admin user if not found
     */
    static async setupAdmin() {
        debug('checking admin user');
        let admin = await User.findOne({
            email: config.admin.email
        });
        if (!admin) {
            debug('create admin user');
            admin = await User.create({
                name: 'Administrator',
                email: config.admin.email,
                roles: [(await Role.findOne({
                    name: 'Admin'
                }))._id],
            });
            admin.setLocalPw(config.admin.passwd);

            await admin.save()
                .then(function (usr, err) {
                    User.findOne({
                        email: config.admin.email
                    }).then(function (user) {
                        if (!user) {
                            debug('error! admin not found!');
                        }
                    });
                });
            return;
        }
        debug('admin exists');
    }

    /**
     * Creates all default roles if not found
     */
    static async setupRoles() {
        debug('checking roles');
        var createRole = async function (name, authObj, authFields) {
            let role = await Role.findOne({
                name: name
            });
            if (!role) {
                debug(`create role: ${name}`);
                role = await Role.create({
                    name: name,
                    buildIn: true,
                });
                Auth.grant(role, authObj, authFields);

                await role.save()
                    .then(function (usr, err) {
                        Role.findOne({
                            name: name
                        }).then(function (r) {
                            if (!r) {
                                debug('error! role not found!');
                            }
                        });
                    });
            } else {
                Auth.grant(role, authObj, authFields);
                await role.save();
            }
        };
        // Default roles
        await createRole('Guest');

        // Ensure Admin role with all possible rights
        for (var [objKey, obj] of Object.entries(Role.authorizationOptions)) {
            let fields = {};
            for (var [fieldKey, field] of Object.entries(obj.fields)) {
                let options = [];
                for (var [optKey, objText] of Object.entries(field.options)) {
                    options.push(optKey);
                }
                fields[fieldKey] = options;
            }
            await createRole('Admin', objKey, fields);
        }
    }

    /**
     * Configures session middleware
     * @param {Object} app - express app instance
     */
    static useSessions(app) {
        // cookie
        let cookie = {
            path: '/',
            maxAge: 365 * 24 * 60 * 60 * 1000,
            httpOnly: false,
        };

        // production vs. dev
        if (app.get('env') === 'production') {
            debug('production environment');
            // trust first proxy
            app.set('trust proxy', 1);
            // serve secure cookies
            cookie.secure = true;
            cookie.httpOnly = true;
        } else {
            debug('development environment');
        }

        app.use(session({
            secret: config.secret,
            name: 'session',
            resave: false,
            saveUninitialized: false,
            cookie: cookie,
            store: new NedbStore({
                filename: __dirname +
                    '/data/sessions.db',
            }),
        }));
    }
}

module.exports = {
    Auth
};