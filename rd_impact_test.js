function query(name) {
  return db.execute("SELECT * FROM users WHERE name = " + name);
}

function getUser(req) {
  return query(req.params.name);
}

function handler(req, res) {
  const u = getUser(req);
  res.send(u);
}
