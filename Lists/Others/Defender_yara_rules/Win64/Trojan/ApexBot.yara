rule Trojan_Win64_ApexBot_Z_2147973253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ApexBot.Z!MTB"
        threat_id = "2147973253"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ApexBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "apex2/Methods.DiscordFlood" ascii //weight: 1
        $x_1_2 = "apex2/Methods.GameFlood" ascii //weight: 1
        $x_1_3 = "apex2/Methods.TLSFlood" ascii //weight: 1
        $x_1_4 = "apex2/Methods.attemptBypass" ascii //weight: 1
        $x_1_5 = "apex2/Methods.dialUTLS" ascii //weight: 1
        $x_1_6 = "apex2/Methods.loadTLSProxies" ascii //weight: 1
        $x_1_7 = "net/http.NewRequest" ascii //weight: 1
        $x_1_8 = "net/http.(*Client).Do" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ApexBot_ZA_2147973254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ApexBot.ZA!MTB"
        threat_id = "2147973254"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ApexBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "go:textfipsend" ascii //weight: 1
        $x_1_2 = "apex2/Bot" ascii //weight: 1
        $x_1_3 = "Discord Attack finished" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

