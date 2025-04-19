const User = require("../../models/userModel/userModel");
const Team = require("../../models/footballModel/teams");

// Maximum number of team members allowed
const MAX_TEAM_MEMBERS = 15;

// Team creation steps
const TEAM_CREATION_STEPS = {
  INITIAL: 1,
  MEMBERS_ADDED: 2,
  CAPTAINS_ASSIGNED: 3,
  COMPLETED: 4,
};

// Controller methods
const teamController = {
  // Step 1: Create a new team (basic details)
  createTeam: async (req, res) => {
    try {
      const { name, description, logo } = req.body;

      // NEW VALIDATION: Check if user is already part of another team
      const isInOtherTeam = await Team.findOne({
        "members.user": req.user.userId,
      });

      if (isInOtherTeam) {
        return res.status(400).json({
          error:
            "You are already a member of another team and cannot create or join multiple teams",
          teamName: isInOtherTeam.name,
        });
      }

      const team = new Team({
        name,
        description,
        logo, // Optional field, will be null if not provided
        owner: req.user.userId,
        // The owner is automatically added as the first member with admin role
        members: [{ user: req.user.userId, role: "admin" }],
        creationStep: TEAM_CREATION_STEPS.INITIAL,
        captain: null,
        viceCaptain: null,
      });

      await team.save();
      res.status(201).json(team);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  },

  // Step 2: Complete adding team members and mark step as completed
  completeTeamMembersStep: async (req, res) => {
    try {
      const team = await Team.findById(req.params.id);
      if (!team) {
        return res.status(404).json({ error: "Team not found" });
      }

      // Check if user has permission (must be a member with admin role or owner)
      const isOwner = team.owner.toString() === req.user.userId.toString();
      const isAdmin = team.members.some(
        (member) =>
          member.user.toString() === req.user.userId.toString() &&
          member.role === "admin"
      );

      if (!isOwner && !isAdmin) {
        return res.status(403).json({ error: "No permission to update team" });
      }

      // Check if team has at least one member (plus the owner/admin)
      if (team.members.length < 2) {
        return res.status(400).json({
          error: "Team must have at least one member besides the owner",
        });
      }

      // Update team creation step
      team.creationStep = TEAM_CREATION_STEPS.MEMBERS_ADDED;
      await team.save();

      res.json(team);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  },

  // Step 3: Assign captain and vice-captain
  assignCaptains: async (req, res) => {
    try {
      const { captain: captainId, viceCaptain: viceCaptainId } = req.body;
      const team = await Team.findById(req.params.id);
      if (!team) {
        return res.status(404).json({ error: "Team not found" });
      }

      // Check if user has permission (must be a member with admin role or owner)
      const isOwner = team.owner.toString() === req.user.userId.toString();
      const isAdmin = team.members.some(
        (member) =>
          member.user.toString() === req.user.userId.toString() &&
          member.role === "admin"
      );

      if (!isOwner && !isAdmin) {
        return res
          .status(403)
          .json({ error: "No permission to assign captains" });
      }

      // Check if team is at the right step
      if (team.creationStep < TEAM_CREATION_STEPS.MEMBERS_ADDED) {
        return res
          .status(400)
          .json({ error: "Please complete adding team members first" });
      }

      // Validate captain and vice-captain are team members
      const isCaptainMember = team.members.some(
        (member) => member.user.toString() === captainId
      );

      const isViceCaptainMember = team.members.some(
        (member) => member.user.toString() === viceCaptainId
      );

      if (!isCaptainMember) {
        return res.status(400).json({ error: "Captain must be a team member" });
      }

      if (!isViceCaptainMember) {
        return res
          .status(400)
          .json({ error: "Vice-captain must be a team member" });
      }

      // Captain and vice-captain cannot be the same person
      if (captainId === viceCaptainId) {
        return res.status(400).json({
          error: "Captain and vice-captain cannot be the same person",
        });
      }

      // Assign captain and vice-captain
      team.captain = captainId;
      team.viceCaptain = viceCaptainId;
      team.creationStep = TEAM_CREATION_STEPS.CAPTAINS_ASSIGNED;

      await team.save();

      // Return updated team with populated captain and vice-captain data
      const updatedTeam = await Team.findById(req.params.id)
        .populate("owner", "name email")
        .populate("members.user", "name email")
        .populate("captain", "name email")
        .populate("viceCaptain", "name email");

      res.json(updatedTeam);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  },

  // Step 4: Complete team creation
  completeTeamCreation: async (req, res) => {
    try {
      const team = await Team.findById(req.params.id);
      if (!team) {
        return res.status(404).json({ error: "Team not found" });
      }

      // Check if user has permission (must be a member with admin role or owner)
      const isOwner = team.owner.toString() === req.user.userId.toString();
      const isAdmin = team.members.some(
        (member) =>
          member.user.toString() === req.user.userId.toString() &&
          member.role === "admin"
      );

      if (!isOwner && !isAdmin) {
        return res
          .status(403)
          .json({ error: "No permission to complete team creation" });
      }

      // Check if all required steps are completed
      if (team.creationStep < TEAM_CREATION_STEPS.CAPTAINS_ASSIGNED) {
        return res
          .status(400)
          .json({ error: "Please assign captain and vice-captain first" });
      }

      // Mark team creation as completed
      team.creationStep = TEAM_CREATION_STEPS.COMPLETED;
      team.createdAt = new Date();

      await team.save();

      // Return completed team
      const completedTeam = await Team.findById(req.params.id)
        .populate("owner", "name email")
        .populate("members.user", "name email")
        .populate("captain", "name email")
        .populate("viceCaptain", "name email");

      res.json(completedTeam);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  },

  // Update team details including logo
  updateTeam: async (req, res) => {
    try {
      const { name, description, logo } = req.body;

      const team = await Team.findById(req.params.id);
      if (!team) {
        return res.status(404).json({ error: "Team not found" });
      }

      // Check if user has permission to update team (must be a member with admin role or owner)
      const isOwner = team.owner.toString() === req.user.userId.toString();
      const isAdmin = team.members.some(
        (member) =>
          member.user.toString() === req.user.userId.toString() &&
          member.role === "admin"
      );

      if (!isOwner && !isAdmin) {
        return res
          .status(403)
          .json({ error: "No permission to update team details" });
      }

      // Update fields if provided
      if (name) team.name = name;
      if (description !== undefined) team.description = description;
      if (logo !== undefined) team.logo = logo;

      await team.save();
      res.json(team);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  },

  // Get the teams
  getAvailaibleTeams: async (req, res) => {
    try {
      if (!req.user || !req.user.userId) {
        return res.status(401).json("Authentication Required");
      }
      const teams = await Team.find({
        creationStep: TEAM_CREATION_STEPS.COMPLETED,
      }).select("_id name logo");

      if (!teams || teams.length === 0) {
        return res.json([]);
      }
      res.json(teams);
    } catch (error) {
      return res.status(500).json({ error: error.message });
    }
  },

  // Get all teams for current user (keeping this as requested)
  getUserTeams: async (req, res) => {
    try {
      // Find teams where user is either owner or member
      const teams = await Team.find({
        $or: [{ owner: req.user.userId }, { "members.user": req.user.userId }],
      })
        .populate("owner", "name email")
        .populate("members.user", "name email")
        .populate("captain", "name email")
        .populate("viceCaptain", "name email");

      res.json(teams);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  },

  // Add a user directly to team by email (modified to work with step system)
  addTeamMember: async (req, res) => {
    try {
      const { email, role = "member" } = req.body;
      // Verify the team exists
      const team = await Team.findById(req.params.id);
      if (!team) {
        return res.status(404).json({ error: "Team not found" });
      }

      // Check if user has permission to add members (must be a member with admin role or owner)
      const isOwner = team.owner.toString() === req.user.userId.toString();
      const isAdmin = team.members.some(
        (member) =>
          member.user.toString() === req.user.userId.toString() &&
          member.role === "admin"
      );

      if (!isOwner && !isAdmin) {
        return res
          .status(403)
          .json({ error: "No permission to add team members" });
      }

      // Check if team is in the right step to add members
      if (team.creationStep > TEAM_CREATION_STEPS.MEMBERS_ADDED) {
        return res
          .status(400)
          .json({ error: "Cannot add members after captain assignment" });
      }

      // Check if team has reached maximum members limit
      if (team.members.length >= MAX_TEAM_MEMBERS) {
        return res.status(400).json({
          error: `Team cannot have more than ${MAX_TEAM_MEMBERS} members`,
        });
      }

      // Verify the user to be added exists by email
      const userToAdd = await User.findOne({ email });
      if (!userToAdd) {
        return res
          .status(404)
          .json({ error: "User not found with the provided email" });
      }

      // Check if user is already a member of this team
      const isMember = team.members.some(
        (member) => member.user.toString() === userToAdd._id.toString()
      );

      if (isMember) {
        return res.status(400).json({ error: "User is already a team member" });
      }

      // NEW VALIDATION: Check if user is a member of any other team
      const isInOtherTeam = await Team.findOne({
        _id: { $ne: team._id }, // Exclude current team
        "members.user": userToAdd._id,
      });

      if (isInOtherTeam) {
        return res.status(400).json({
          error:
            "User is already a member of another team and cannot join multiple teams",
          teamName: isInOtherTeam.name, // Optional: Provide the name of the other team
        });
      }

      // Add the user directly to the team
      team.members.push({
        user: userToAdd._id,
        role: role, // Can be "admin" or "member"
        joinedAt: new Date(),
      });

      await team.save();

      // Return updated team with populated user data
      const updatedTeam = await Team.findById(req.params.id)
        .populate("owner", "name email")
        .populate("members.user", "name email");

      res.json(updatedTeam);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  },

  // Remove a team member
  removeTeamMember: async (req, res) => {
    try {
      const team = await Team.findById(req.params.id);
      if (!team) {
        return res.status(404).json({ error: "Team not found" });
      }

      // Check if user has permission (must be admin, owner or removing self)
      const isOwner = team.owner.toString() === req.user.userId.toString();
      const isAdmin = team.members.some(
        (member) =>
          member.user.toString() === req.user.userId.toString() &&
          member.role === "admin"
      );
      const isSelf = req.params.userId === req.user.userId.toString();

      if (!isOwner && !isAdmin && !isSelf) {
        return res
          .status(403)
          .json({ error: "No permission to remove team members" });
      }

      // Cannot remove the owner
      if (team.owner.toString() === req.params.userId && !isSelf) {
        return res.status(400).json({ error: "Cannot remove team owner" });
      }

      // Check if team is in the right step to remove members
      if (team.creationStep > TEAM_CREATION_STEPS.MEMBERS_ADDED) {
        // Check if attempting to remove captain or vice-captain
        if (
          (team.captain && team.captain.toString() === req.params.userId) ||
          (team.viceCaptain &&
            team.viceCaptain.toString() === req.params.userId)
        ) {
          return res.status(400).json({
            error:
              "Cannot remove captain or vice-captain after they have been assigned",
          });
        }
      }

      // Remove the user
      team.members = team.members.filter(
        (member) => member.user.toString() !== req.params.userId
      );

      await team.save();
      res.json(team);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  },

  // Get team details
  getTeamDetails: async (req, res) => {
    try {
      const team = await Team.findById(req.params.id)
        .populate("owner", "name email")
        .populate("members.user", "name email")
        .populate("captain", "name email")
        .populate("viceCaptain", "name email");

      if (!team) {
        return res.status(404).json({ error: "Team not found" });
      }

      // Check if user is authorized to see team details
      const isMember = team.members.some(
        (member) =>
          member.user._id &&
          member.user._id.toString() === req.user.userId.toString()
      );
      const isOwner =
        team.owner._id &&
        team.owner._id.toString() === req.user.userId.toString();

      if (!isMember && !isOwner) {
        return res
          .status(403)
          .json({ error: "Not authorized to view this team" });
      }

      res.json(team);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  },

  // Get team creation status
  getTeamCreationStatus: async (req, res) => {
    try {
      const team = await Team.findById(req.params.id);

      if (!team) {
        return res.status(404).json({ error: "Team not found" });
      }

      // Check if user is authorized
      const isMember = team.members.some(
        (member) => member.user.toString() === req.user.userId.toString()
      );
      const isOwner = team.owner.toString() === req.user.userId.toString();

      if (!isMember && !isOwner) {
        return res
          .status(403)
          .json({ error: "Not authorized to view this team" });
      }

      // Return team creation status
      const status = {
        teamId: team._id,
        currentStep: team.creationStep,
        steps: {
          1: "Initial team creation",
          2: "Team members added",
          3: "Captain and vice-captain assigned",
          4: "Team creation completed",
        },
        completed: team.creationStep === TEAM_CREATION_STEPS.COMPLETED,
        membersCount: team.members.length,
        maxMembers: MAX_TEAM_MEMBERS,
        captainAssigned: !!team.captain,
        viceCaptainAssigned: !!team.viceCaptain,
      };

      res.json(status);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  },

  // Update team member role (promotes or demotes between admin and member)
  updateMemberRole: async (req, res) => {
    try {
      const { userId, role } = req.body;

      if (!["admin", "member"].includes(role)) {
        return res
          .status(400)
          .json({ error: "Role must be either 'admin' or 'member'" });
      }

      const team = await Team.findById(req.params.id);
      if (!team) {
        return res.status(404).json({ error: "Team not found" });
      }

      // Check if the requester has permission (must be owner or admin)
      const isOwner = team.owner.toString() === req.user.userId.toString();
      const isAdmin = team.members.some(
        (member) =>
          member.user.toString() === req.user.userId.toString() &&
          member.role === "admin"
      );

      if (!isOwner && !isAdmin) {
        return res
          .status(403)
          .json({ error: "No permission to update member roles" });
      }

      // Cannot demote the owner from admin role
      if (team.owner.toString() === userId && role !== "admin") {
        return res
          .status(400)
          .json({ error: "Cannot change the role of the team owner" });
      }

      // Find the member to update
      const memberIndex = team.members.findIndex(
        (member) => member.user.toString() === userId
      );

      if (memberIndex === -1) {
        return res
          .status(404)
          .json({ error: "User is not a member of this team" });
      }

      // Update the role
      team.members[memberIndex].role = role;
      await team.save();

      // Return updated team
      const updatedTeam = await Team.findById(req.params.id)
        .populate("owner", "name email")
        .populate("members.user", "name email")
        .populate("captain", "name email")
        .populate("viceCaptain", "name email");

      res.json(updatedTeam);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  },

  removeTeam: async (req, res) => {
    try {
      const { id } = req.params;
      const userId = req.user.userId; // Assuming authentication middleware sets req.user

      // Find the team by ID
      const team = await Team.findById(id);

      if (!team) {
        return res.status(404).json({ error: "Team not found" });
      }

      // Check if the requesting user is the owner
      if (team.owner.toString() !== userId) {
        return res
          .status(403)
          .json({ error: "Only the team owner can delete this team" });
      }

      // Delete the team
      await Team.findByIdAndDelete(id);

      res.status(200).json({ message: "Team deleted successfully" });
    } catch (error) {
      console.error("Error deleting team:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  },
};

module.exports = teamController;
