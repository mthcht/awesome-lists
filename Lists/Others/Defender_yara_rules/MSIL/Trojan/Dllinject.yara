rule Trojan_MSIL_Dllinject_KB_2147758159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dllinject.KB"
        threat_id = "2147758159"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dllinject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<krnl_Activated>d__110" ascii //weight: 1
        $x_1_2 = "krnlss.exe" ascii //weight: 1
        $x_1_3 = "injection" ascii //weight: 1
        $x_1_4 = "krnl_monaco" ascii //weight: 1
        $x_1_5 = "krnlss.krnl.resources" ascii //weight: 1
        $x_1_6 = "krnl_Load" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dllinject_CA_2147807565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dllinject.CA!MTB"
        threat_id = "2147807565"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dllinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://api.thundermods.com/downloads/EasyExploits.dll" ascii //weight: 1
        $x_1_2 = "https://raw.githubusercontent.com/RandomAdamYT/DarkHub/master/Init" ascii //weight: 1
        $x_1_3 = "https://pastebin.com/raw/imEAQX7q" ascii //weight: 1
        $x_1_4 = "wearedevs.net" ascii //weight: 1
        $x_1_5 = "HTTPDebuggerPro" ascii //weight: 1
        $x_1_6 = "Hacker" ascii //weight: 1
        $x_1_7 = "Skisploit.dll" ascii //weight: 1
        $x_1_8 = "http://api.thundermods.com/updatemessage.txt" ascii //weight: 1
        $x_1_9 = "Injected" ascii //weight: 1
        $x_1_10 = "Download it from http://bit.ly/cretributions" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

