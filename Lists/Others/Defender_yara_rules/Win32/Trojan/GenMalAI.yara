rule Trojan_Win32_GenMalAI_AI_2147952855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GenMalAI.AI!sms"
        threat_id = "2147952855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GenMalAI"
        severity = "Critical"
        info = "sms: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "prompt" ascii //weight: 1
        $x_1_2 = "user:" ascii //weight: 1
        $x_1_3 = "messages:" ascii //weight: 1
        $x_1_4 = "assistant" ascii //weight: 1
        $x_1_5 = "model" ascii //weight: 1
        $x_1_6 = "input" ascii //weight: 1
        $x_1_7 = "temperature" ascii //weight: 1
        $x_1_8 = "instruction" ascii //weight: 1
        $x_1_9 = "role" ascii //weight: 1
        $x_1_10 = "content" ascii //weight: 1
        $x_1_11 = "subprocess" ascii //weight: 1
        $x_1_12 = "token=" ascii //weight: 1
        $x_1_13 = "max_tokens" ascii //weight: 1
        $x_1_14 = "top_p" ascii //weight: 1
        $x_1_15 = "stream\": true" ascii //weight: 1
        $x_1_16 = "Bearer " ascii //weight: 1
        $x_1_17 = "api_key" ascii //weight: 1
        $x_1_18 = "safetensors" ascii //weight: 1
        $x_1_19 = "gpt-" ascii //weight: 1
        $x_1_20 = "claude" ascii //weight: 1
        $x_1_21 = "llama" ascii //weight: 1
        $x_1_22 = "vicuna" ascii //weight: 1
        $x_1_23 = "mistral" ascii //weight: 1
        $x_1_24 = "falcon" ascii //weight: 1
        $x_1_25 = "bison" ascii //weight: 1
        $x_1_26 = "post /v1/completions" ascii //weight: 1
        $x_1_27 = "function encrypt" ascii //weight: 1
        $x_1_28 = "function exfiltrate" ascii //weight: 1
        $x_1_29 = "os.execute" ascii //weight: 1
        $x_1_30 = "llm_endpoint" ascii //weight: 1
        $x_1_31 = "api.openai.com" ascii //weight: 1
        $x_1_32 = "ollama.com" ascii //weight: 1
        $x_1_33 = "inference.huggingface.co" ascii //weight: 1
        $x_1_34 = "api.replicate.com" ascii //weight: 1
        $x_1_35 = "api.anthropic.com" ascii //weight: 1
        $x_1_36 = "api.cohere.ai" ascii //weight: 1
        $x_1_37 = "aiplatform.googleapis.com" ascii //weight: 1
        $x_1_38 = "bedrock-runtime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

