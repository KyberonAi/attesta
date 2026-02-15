/**
 * Challenge modules for attesta.
 *
 * Each challenge corresponds to a different risk level and verification strategy:
 * - ConfirmChallenge: Simple Y/N for MEDIUM risk
 * - QuizChallenge: Comprehension quiz for HIGH risk
 * - TeachBackChallenge: Free-text explanation for CRITICAL risk
 */

export { ConfirmChallenge } from "./confirm.js";
export type { ConfirmChallengeOptions } from "./confirm.js";

export { QuizChallenge } from "./quiz.js";
export type { QuizChallengeOptions, Question } from "./quiz.js";

export { TeachBackChallenge } from "./teach-back.js";
export type { TeachBackChallengeOptions } from "./teach-back.js";

export { KeywordValidator } from "./validators.js";
export type { TeachBackValidator } from "./validators.js";
