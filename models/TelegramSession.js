const mongoose = require("mongoose");

const TelegramSessionSchema = new mongoose.Schema({
  tenantId: { type: String, required: true },
  agentId: { type: String, required: true },
  agentExtension: { type: String, required: true },

  session: { type: String, required: true },
  phoneNumber: { type: String },
  extension: { type: String },

  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

TelegramSessionSchema.index({ tenantId: 1, agentId: 1 }, { unique: true });

module.exports = mongoose.model("TelegramSession", TelegramSessionSchema);
