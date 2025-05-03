const express = require("express");
const router = express.Router();
const teamController = require("../../controller/badmintonAPIController/teamController");

// Middleware to check authentication can be added here if needed

// Create a new team
router.post("/", teamController.createTeam);

// Complete adding team members step
router.put("/:id/complete-members", teamController.completeTeamMembersStep);

// Assign captain and vice-captain
router.put("/:id/assign-captains", teamController.assignCaptains);

// Complete team creation
router.put("/:id/complete-creation", teamController.completeTeamCreation);

// Update team details
router.put("/:id", teamController.updateTeam);

// Get available teams
router.get("/available", teamController.getAvailaibleTeams);

// Get teams for current user
router.get("/user-teams", teamController.getUserTeams);

// Add team member by email
router.post("/:id/members", teamController.addTeamMember);

// Remove team member
router.delete("/:id/members/:userId", teamController.removeTeamMember);

// Get team details
router.get("/:id", teamController.getTeamDetails);

// Get team creation status
router.get("/:id/creation-status", teamController.getTeamCreationStatus);

// Update team member role
router.put("/:id/members/role", teamController.updateMemberRole);

// Remove team
router.delete("/:id", teamController.removeTeam);

module.exports = router;
