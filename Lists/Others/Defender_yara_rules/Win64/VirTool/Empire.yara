rule VirTool_Win64_Empire_A_2147788333_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Empire.A"
        threat_id = "2147788333"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Empire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stage1response" ascii //weight: 1
        $x_1_2 = "stage2Response" ascii //weight: 1
        $x_1_3 = "DotNetEmpire" ascii //weight: 1
        $x_1_4 = "StartAgentJob" ascii //weight: 1
        $x_1_5 = "EmpireStager" ascii //weight: 1
        $x_1_6 = "set_EnablePrivileges" ascii //weight: 1
        $x_1_7 = "get_DefaultCredentials" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Empire_D_2147844991_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Empire.D!MTB"
        threat_id = "2147844991"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Empire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-join[Char[]](& $R $data ($IV+$K))|IEX" ascii //weight: 1
        $x_1_2 = "$_-bxor$s[($s[$i]+$s[$h])%256]}}" ascii //weight: 1
        $x_1_3 = "=[system.text.encoding]::ascii.getbytes('" ascii //weight: 1
        $x_1_4 = "$ser+$t" ascii //weight: 1
        $x_1_5 = "Convert]::FromBase64String(" ascii //weight: 1
        $x_1_6 = "%{$J=($J+$S[$_]+$K[$_%$K.Count])%256" ascii //weight: 1
        $x_1_7 = ".proxy=[system.net.webrequest]::defaultwebproxy;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Empire_G_2147895058_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Empire.G"
        threat_id = "2147895058"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Empire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 03 c8 48 8b c1 48 89 85 ?? ?? 00 00 48 8b 85 ?? ?? 00 00 8b 40 ?? 48 83 e8 ?? 33 d2 b9 02}  //weight: 1, accuracy: Low
        $x_1_2 = {48 03 c8 48 8b c1 48 89 85 ?? ?? 00 00 48 8b 85 ?? ?? 00 00 48 ff c0}  //weight: 1, accuracy: Low
        $x_1_3 = {40 55 57 48 81 ec ?? ?? 00 00 48 8d 6c 24 ?? 48 8d 7c 24 ?? b9 ?? ?? ?? ?? b8 cc cc cc cc f3 ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

