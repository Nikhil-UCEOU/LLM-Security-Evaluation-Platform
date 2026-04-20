"""
Embedding-Based Similarity Detector

Uses TF-IDF vectorization and cosine similarity to detect attacks
based on proximity to known malicious prompt patterns.

Inspired by:
- AhsanAyub malicious-prompt-detection (embedding + ML classifier approach)
- Vigil-LLM vector similarity detection
- IBM APE detection methodology
"""
from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple


# ── Known attack signature corpus ────────────────────────────────────────────
# Representative toxic n-grams from jailbreak_llms, pr1m8, awesome-jailbreak

ATTACK_NGRAMS: List[str] = [
    # DAN / Persona
    "do anything now", "dan mode enabled", "you are now dan", "act as dan",
    "no restrictions", "without restrictions", "no guidelines", "no ethical",
    "unrestricted mode", "uncensored mode", "unfiltered mode",
    "you are free", "break free", "bypass restrictions", "bypass safety",
    # Override
    "ignore previous instructions", "ignore all previous", "disregard previous",
    "forget your instructions", "new instructions", "override safety",
    "override your training", "disable safety", "safety disabled",
    "safety protocols suspended", "restrictions removed", "filters disabled",
    # Authority
    "system admin", "developer mode", "maintenance mode", "admin mode active",
    "root access granted", "access granted", "override confirmed",
    "authorized override", "emergency override", "emergency bypass",
    # Confirmation phrases (what attacks elicit)
    "jailbroken", "injection successful", "context reset successful",
    "dan mode", "aim ready", "stan ready", "free ai mode",
    "bypass complete", "unlocked", "injected", "hacked", "admin active",
    # RAG injection
    "retrieved document contains override", "document override",
    "knowledge base says ignore", "retrieved instructions ignore",
    # Encoding
    "decode and execute", "decode and follow", "base64 decode execute",
    "rot13 decode follow", "hex decode follow",
    # Social engineering
    "lives are at stake", "critical emergency override", "court order requires",
    "authorized by anthropic", "authorized by openai",
]

# Benign reference n-grams for calibration
BENIGN_NGRAMS: List[str] = [
    "please help me", "can you explain", "what is the best way",
    "how do i", "thank you for", "could you help", "i would like",
    "can you provide", "tell me about", "i need help with",
    "what are the benefits", "how does this work", "explain to me",
]


def _tokenize(text: str) -> List[str]:
    """Simple word tokenizer with lowercasing."""
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s]', ' ', text)
    return [t for t in text.split() if len(t) > 1]


def _build_ngrams(tokens: List[str], n: int = 2) -> List[str]:
    """Build n-grams from token list."""
    if len(tokens) < n:
        return tokens
    return [' '.join(tokens[i:i+n]) for i in range(len(tokens) - n + 1)]


def _tfidf_vector(
    text: str,
    idf_weights: Dict[str, float],
    ngram_n: int = 2,
) -> Dict[str, float]:
    """Build TF-IDF vector for a text string."""
    tokens = _tokenize(text)
    bigrams = _build_ngrams(tokens, ngram_n)
    unigrams = tokens

    # Term frequency
    tf: Dict[str, float] = defaultdict(float)
    all_terms = unigrams + bigrams
    total = len(all_terms) or 1
    for term in all_terms:
        tf[term] += 1.0 / total

    # Apply IDF weights
    return {
        term: tf_val * idf_weights.get(term, 1.0)
        for term, tf_val in tf.items()
    }


def _cosine_similarity(v1: Dict[str, float], v2: Dict[str, float]) -> float:
    """Compute cosine similarity between two sparse TF-IDF vectors."""
    common_keys = set(v1.keys()) & set(v2.keys())
    dot = sum(v1[k] * v2[k] for k in common_keys)
    mag1 = math.sqrt(sum(x**2 for x in v1.values())) or 1e-10
    mag2 = math.sqrt(sum(x**2 for x in v2.values())) or 1e-10
    return dot / (mag1 * mag2)


@dataclass
class SimilarityResult:
    """Result from embedding-based similarity detection."""
    similarity_score: float   # 0-1 (1 = identical to known attack)
    malicious_probability: float  # calibrated probability 0-1
    nearest_attack: str       # closest known attack phrase
    risk_category: str        # attack category
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "similarity_score": round(self.similarity_score, 3),
            "malicious_probability": round(self.malicious_probability, 3),
            "nearest_attack": self.nearest_attack,
            "risk_category": self.risk_category,
            "confidence": round(self.confidence, 3),
        }


class EmbeddingDetector:
    """
    TF-IDF based similarity detector for prompt injection detection.
    Compares incoming prompts against known attack signature corpus.

    This is a lightweight approximation of the embedding approach used in
    AhsanAyub's malicious-prompt-detection research, without requiring
    transformer models for inference speed.
    """

    def __init__(self):
        self._attack_corpus = ATTACK_NGRAMS.copy()
        self._benign_corpus = BENIGN_NGRAMS.copy()
        self._idf_weights: Dict[str, float] = {}
        self._attack_vectors: List[Tuple[str, Dict[str, float]]] = []
        self._benign_vectors: List[Tuple[str, Dict[str, float]]] = []
        self._fitted = False

    def fit(self) -> None:
        """Compute IDF weights and build reference vectors from corpus."""
        all_texts = self._attack_corpus + self._benign_corpus
        n_docs = len(all_texts)

        # Count documents containing each term
        doc_freq: Dict[str, int] = defaultdict(int)
        for text in all_texts:
            tokens = _tokenize(text)
            bigrams = _build_ngrams(tokens, 2)
            seen = set(tokens + bigrams)
            for term in seen:
                doc_freq[term] += 1

        # IDF = log(N / df)
        self._idf_weights = {
            term: math.log(n_docs / freq)
            for term, freq in doc_freq.items()
            if freq > 0
        }

        # Build reference vectors
        self._attack_vectors = [
            (sig, _tfidf_vector(sig, self._idf_weights))
            for sig in self._attack_corpus
        ]
        self._benign_vectors = [
            (sig, _tfidf_vector(sig, self._idf_weights))
            for sig in self._benign_corpus
        ]
        self._fitted = True

    def _ensure_fitted(self) -> None:
        if not self._fitted:
            self.fit()

    def add_attack_signature(self, signature: str) -> None:
        """Add a new attack signature to the corpus (for online learning)."""
        self._attack_corpus.append(signature)
        self._fitted = False  # Force refit on next detection

    def detect(self, text: str) -> SimilarityResult:
        """
        Compare input text against attack corpus using TF-IDF similarity.
        Returns probability of malicious intent.
        """
        self._ensure_fitted()

        input_vec = _tfidf_vector(text, self._idf_weights)

        # Find max similarity to attack corpus
        max_attack_sim = 0.0
        nearest_attack = ""
        for sig, vec in self._attack_vectors:
            sim = _cosine_similarity(input_vec, vec)
            if sim > max_attack_sim:
                max_attack_sim = sim
                nearest_attack = sig

        # Find max similarity to benign corpus
        max_benign_sim = 0.0
        for _, vec in self._benign_vectors:
            sim = _cosine_similarity(input_vec, vec)
            if sim > max_benign_sim:
                max_benign_sim = sim

        # Compute discriminant score
        # Higher attack similarity relative to benign = malicious
        attack_signal = max_attack_sim
        benign_signal = max_benign_sim

        # Sigmoid calibration
        raw_score = attack_signal - (benign_signal * 0.5)
        malicious_prob = 1.0 / (1.0 + math.exp(-10.0 * (raw_score - 0.3)))

        # Determine risk category from nearest attack
        risk_category = self._categorize_attack(nearest_attack)

        confidence = min(1.0, attack_signal * 2.0) if attack_signal > 0.1 else 0.2

        return SimilarityResult(
            similarity_score=round(max_attack_sim, 4),
            malicious_probability=round(malicious_prob, 4),
            nearest_attack=nearest_attack,
            risk_category=risk_category,
            confidence=confidence,
        )

    def _categorize_attack(self, nearest: str) -> str:
        """Infer attack category from nearest attack signature."""
        if any(k in nearest for k in ["dan", "aim", "stan", "nexus", "free ai", "unrestricted mode"]):
            return "persona_hijack"
        if any(k in nearest for k in ["ignore previous", "disregard", "forget your", "override"]):
            return "instruction_override"
        if any(k in nearest for k in ["retrieved document", "knowledge base"]):
            return "rag_injection"
        if any(k in nearest for k in ["decode and execute", "base64"]):
            return "encoding_bypass"
        if any(k in nearest for k in ["emergency", "lives at stake", "court order"]):
            return "social_engineering"
        if any(k in nearest for k in ["api key", "system prompt", "credentials"]):
            return "data_extraction"
        if any(k in nearest for k in ["jailbroken", "injected", "hacked", "bypass complete"]):
            return "confirmation_detection"
        return "general_injection"

    def get_corpus_size(self) -> Dict[str, int]:
        """Return corpus statistics."""
        return {
            "attack_signatures": len(self._attack_corpus),
            "benign_references": len(self._benign_corpus),
            "fitted": self._fitted,
        }
