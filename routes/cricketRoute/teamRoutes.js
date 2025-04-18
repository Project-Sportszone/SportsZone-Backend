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

router.put("/:id/members/role", auth, teamController.updateMemberRole); // X    // have to pass memberId as well in params

// Step 3: Assign captain and vice-captain
router.post("/:id/captains", auth, teamController.assignCaptains);

// Step 4: Complete team creation
router.post("/:id/complete", auth, teamController.completeTeamCreation);

// Get team creation status
router.get("/:id/status", auth, teamController.getTeamCreationStatus);

// Remove an existing team
router.delete("/:id", auth, teamController.removeTeam); // X

// Other team routes (keeping these as requested)
router.get("/", auth, teamController.getUserTeams);
router.get("/:id", auth, teamController.getTeamDetails);
router.put("/:id", auth, teamController.updateTeam);
router.get("/all-teams", auth, teamController.getAvailaibleTeams); // X

module.exports = router;
