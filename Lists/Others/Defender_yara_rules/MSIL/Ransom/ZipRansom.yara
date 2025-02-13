rule Ransom_MSIL_ZipRansom_YAA_2147925029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/ZipRansom.YAA!MTB"
        threat_id = "2147925029"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZipRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fuckyousomware.Resources" wide //weight: 1
        $x_1_2 = "ZIPLOCK_LOG.txt" wide //weight: 1
        $x_1_3 = "%ENCRYPTED_ID%" wide //weight: 1
        $x_1_4 = "Hey analysis team, try decrypt this, you do my last variant. No more!" wide //weight: 1
        $x_1_5 = "BLACKLISTED FILETYPE" wide //weight: 1
        $x_1_6 = "INSTRUCTIONS.txt" wide //weight: 1
        $x_1_7 = "Start-Sleep -Seconds 5; Remove-Item " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

