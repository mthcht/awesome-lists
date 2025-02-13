rule HackTool_Win64_JuicyPotato_SBR_2147755358_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/JuicyPotato.SBR!MSR"
        threat_id = "2147755358"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "JuicyPotato"
        severity = "High"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JuicyPotato.pdb" ascii //weight: 1
        $x_1_2 = "Waiting for auth" ascii //weight: 1
        $x_1_3 = "shutdown" ascii //weight: 1
        $x_1_4 = "AquireCredential" ascii //weight: 1
        $x_1_5 = "hello.stg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_JuicyPotato_LK_2147838812_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/JuicyPotato.LK!MTB"
        threat_id = "2147838812"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "JuicyPotato"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JuicyPotatoNG" ascii //weight: 1
        $x_1_2 = "by decoder_it & splinter_code" ascii //weight: 1
        $x_1_3 = "[+] Exploit successful!" ascii //weight: 1
        $x_1_4 = "[!] CryptStringToBinaryW failed with error code %d" ascii //weight: 1
        $x_1_5 = "ncacn_ip_tcp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

