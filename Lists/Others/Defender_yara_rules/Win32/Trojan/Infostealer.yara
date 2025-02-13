rule Trojan_Win32_Infostealer_PAH_2147781482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Infostealer.PAH!MTB"
        threat_id = "2147781482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Infostealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" ascii //weight: 1
        $x_1_2 = "My saved passwords - Notepad" ascii //weight: 1
        $x_1_3 = "Internet Explorer_Server" ascii //weight: 1
        $x_1_4 = "Bank of America log-in" ascii //weight: 1
        $x_1_5 = "CityBank log-in" ascii //weight: 1
        $x_1_6 = "A:\\||||||||||||.swf" ascii //weight: 1
        $x_1_7 = "Yahoo! Messenger" ascii //weight: 1
        $x_1_8 = "tooltips_class32" ascii //weight: 1
        $x_1_9 = "antivirus.exe" ascii //weight: 1
        $x_1_10 = "pt_login_sig=" ascii //weight: 1
        $x_1_11 = "winlogon.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Infostealer_HBAI_2147808774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Infostealer.HBAI!MTB"
        threat_id = "2147808774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Infostealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Sosoponazubirin" ascii //weight: 2
        $x_2_2 = "wexeta" ascii //weight: 2
        $x_2_3 = "keletolazekemamar" ascii //weight: 2
        $x_2_4 = "ribehupovacavalotepenegedicug" ascii //weight: 2
        $x_2_5 = "Senovul" ascii //weight: 2
        $x_2_6 = "CIDAFICUDUROSOTAROM" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

