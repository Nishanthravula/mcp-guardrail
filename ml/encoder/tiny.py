"""A tiny tokenizer and ModernBERT model, for testing the pipeline without a GPU.

They have the same architecture and file formats as the real model, so export,
quantisation and Node loading are exercised end to end. Their scores mean
nothing.
"""

from __future__ import annotations

SPECIAL = ["[UNK]", "[CLS]", "[SEP]", "[PAD]", "[MASK]"]


def build_tokenizer(texts, vocab_size: int = 600):
    from tokenizers import Tokenizer, decoders, models, pre_tokenizers, processors, trainers
    from transformers import PreTrainedTokenizerFast

    tok = Tokenizer(models.BPE(unk_token=None))
    tok.pre_tokenizer = pre_tokenizers.ByteLevel(add_prefix_space=False)
    tok.decoder = decoders.ByteLevel()
    trainer = trainers.BpeTrainer(
        vocab_size=vocab_size, special_tokens=SPECIAL, initial_alphabet=pre_tokenizers.ByteLevel.alphabet()
    )
    tok.train_from_iterator(texts, trainer)
    tok.post_processor = processors.TemplateProcessing(
        single="[CLS] $A [SEP]", special_tokens=[("[CLS]", 1), ("[SEP]", 2)]
    )
    return PreTrainedTokenizerFast(
        tokenizer_object=tok, unk_token="[UNK]", cls_token="[CLS]", sep_token="[SEP]",
        pad_token="[PAD]", mask_token="[MASK]", model_max_length=512,
    )


def build_model(tokenizer, seed: int = 0):
    import torch
    from transformers import ModernBertConfig, ModernBertForSequenceClassification

    cfg = ModernBertConfig(
        vocab_size=len(tokenizer), hidden_size=32, intermediate_size=64, num_hidden_layers=3,
        num_attention_heads=2, max_position_embeddings=512, num_labels=2,
        pad_token_id=tokenizer.pad_token_id, cls_token_id=tokenizer.cls_token_id,
        sep_token_id=tokenizer.sep_token_id, bos_token_id=tokenizer.cls_token_id,
        eos_token_id=tokenizer.sep_token_id,
        # As in ModernBERT-base: one global-attention layer, then sliding-window layers.
        global_attn_every_n_layers=3, local_attention=128,
    )
    torch.manual_seed(seed)
    return ModernBertForSequenceClassification._from_config(cfg, attn_implementation="sdpa")
