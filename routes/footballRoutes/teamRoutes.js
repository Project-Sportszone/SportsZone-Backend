const express = require("express");
const router = express.Router();
const authMiddleware = require("../../middleware/auth_middleware");
const teamController = require("../../controller/footballAPIController/teamController");

// Middleware to check authentication can be added here if needed

// Create a new team
router.post("/", authMiddleware, teamController.createTeam);

// Complete adding team members step
router.put(
  "/:id/complete-members",
  authMiddleware,
  teamController.completeTeamMembersStep
);

// Assign captain and vice-captain
router.put(
  "/:id/assign-captains",
  authMiddleware,
  teamController.assignCaptains
);

// Complete team creation
router.put(
  "/:id/complete-creation",
  authMiddleware,
  teamController.completeTeamCreation
);

// Update team details
router.put("/:id", authMiddleware, teamController.updateTeam);

// Get available teams
router.get("/available", authMiddleware, teamController.getAvailaibleTeams);

// Get teams for current user
router.get("/user-teams", authMiddleware, teamController.getUserTeams);

// Add team member by email
router.post("/:id/members", authMiddleware, teamController.addTeamMember);

// Remove team member
router.delete(
  "/:id/members/:userId",
  authMiddleware,
  teamController.removeTeamMember
);

// Get team details
router.get("/:id", authMiddleware, teamController.getTeamDetails);

// Get team creation status
router.get(
  "/:id/creation-status",
  authMiddleware,
  teamController.getTeamCreationStatus
);

// Update team member role
router.put(
  "/:id/members/role",
  authMiddleware,
  teamController.updateMemberRole
);

// Remove team
router.delete("/:id", authMiddleware, teamController.removeTeam);

module.exports = router;
