rule Ransom_Win64_Rents_ABKV_2147971514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Rents.ABKV!MTB"
        threat_id = "2147971514"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Rents"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VBOX" ascii //weight: 1
        $x_1_2 = "%s!!!READ_ME_NOW!!!.html" ascii //weight: 1
        $x_1_3 = "CryptEncrypt" ascii //weight: 1
        $x_1_4 = "Created HTML ransom note" ascii //weight: 1
        $x_1_5 = "Processes killed" ascii //weight: 1
        $x_1_6 = "Services disabled" ascii //weight: 1
        $x_1_7 = "Shadow copies deleted" ascii //weight: 1
        $x_1_8 = "C2 connected" ascii //weight: 1
        $x_1_9 = "Total bytes encrypted" ascii //weight: 1
        $x_1_10 = "phantom_wallpaper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

