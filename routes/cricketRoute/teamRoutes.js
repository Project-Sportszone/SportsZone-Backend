const express = require("express");
const router = express.Router();
const teamController = require("../../controller/cricketAPIController/teamController");
const auth = require("../../middleware/auth_middleware");

// Step 1: Create a new team (basic details)
router.post("/createteam", auth, teamController.createTeam);

// Step 2: Add team members
router.post("/:id/members", auth, teamController.addTeamMember);
router.delete("/:id/members/:userId", auth, teamController.removeTeamMember);
router.post(
  "/:id/complete-members",
  auth,
  teamController.completeTeamMembersStep
);

router.put("/:id/members/role", auth, teamController.updateMemberRole);

// Step 3: Assign captain and vice-captain
router.post("/:id/captains", auth, teamController.assignCaptains);

// Step 4: Complete team creation
router.post("/:id/complete", auth, teamController.completeTeamCreation);

// Get team creation status
router.get("/teams/:id/status", auth, teamController.getTeamCreationStatus);

// Other team routes (keeping these as requested)
router.get("/teams", auth, teamController.getUserTeams);
router.get("/teams/:id", auth, teamController.getTeamDetails);
router.put("/teams/:id", auth, teamController.updateTeam);
router.get("/all-teams", auth, teamController.getAvailaibleTeams);

router.post("/:id/assign-admin", auth, teamController.assignAdmin);

// Add or remove players later
router.put("/:id/update-players", auth, teamController.updateTeamPlayers);

// Update captain and vice-captain later
router.put("/:id/update-captains", auth, teamController.updateCaptains);
// Show all team members
router.get("/:id/members", auth, teamController.getTeamMembers);

// Add a new team member
router.post("/:id/members", auth, teamController.addTeamMember);

// Remove a team member
router.delete("/:id/members/:userId", auth, teamController.removeTeamMember);

// Change the admin of the team
router.put("/:id/change-admin", auth, teamController.changeAdmin);
router.get("/owned-teams", auth, teamController.getOwnedTeams);
module.exports = router;
