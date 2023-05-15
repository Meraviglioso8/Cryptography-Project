const express = require('express');
const app = express();

// Middleware for access control
function authorizeUser(allowedRoles) {
    return (req, res, next) => {
      if (!req.isAuthenticated()) {
        return res.status(401).send('Unauthorized');
      }
      const userRole = req.user.role;
      if (!allowedRoles.includes(userRole)) {
        return res.status(403).send('Access denied');
      }
      next();
    };
  }

// Middleware to check file permissions
function checkRolePermission(permission) {
  return (req, res, next) => {
    const userRole = req.user.role;
    if (!userRole.permissions.includes(permission)) {
      return res.status(403).send('Access denied');
    }
    next();
  };
}

// Middleware to check file ownership
function checkFileOwnership(req, res, next) {
    const fileId = req.params.fileId;
    // Check if file belongs to authenticated user
    const file = getFileById(fileId);
    if (!file || file.owner !== req.user.id) {
        return res.status(403).send('Access denied');
    }
    next();
}


