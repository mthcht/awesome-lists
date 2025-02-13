rule TrojanDownloader_BAT_Obfuse_PAEZ_2147918099_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:BAT/Obfuse.PAEZ!MTB"
        threat_id = "2147918099"
        type = "TrojanDownloader"
        platform = "BAT: Basic scripts"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c \"payload.bat\"" ascii //weight: 1
        $x_1_2 = "RUNPROGRAM" ascii //weight: 1
        $x_1_3 = "REBOOT" ascii //weight: 1
        $x_1_4 = "msdownld.tmp" ascii //weight: 1
        $x_1_5 = "wextract.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

