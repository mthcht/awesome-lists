rule Ransom_Win64_Hermes_A_2147889447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Hermes.A!MTB"
        threat_id = "2147889447"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Hermes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "net stop" ascii //weight: 2
        $x_2_2 = "taskkill /f  /im" ascii //weight: 2
        $x_2_3 = "/C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\"" wide //weight: 2
        $x_2_4 = "vssadmin delete shadows / all / quiet" wide //weight: 2
        $x_2_5 = "wmic shadowcopy delete & bcdedit / set{ default } bootstatuspolicy ignoreallfailures" wide //weight: 2
        $x_2_6 = "bcdedit / set{ default } recoveryenabled no" wide //weight: 2
        $x_2_7 = "wbadmin delete catalog - quiet" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

