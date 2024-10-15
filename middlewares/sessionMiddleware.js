exports.validateSession = (req, res, next) => {
    const sessionId = req.cookies.sessionId;

    if (!sessionId || !req.sessionStore.get(sessionId)) {
        return res.status(401).send('Invalid session');
    }

    next();
};
