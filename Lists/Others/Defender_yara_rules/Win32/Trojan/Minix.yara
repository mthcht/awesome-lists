rule Trojan_Win32_Minix_NLA_2147896863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Minix.NLA!MTB"
        threat_id = "2147896863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Minix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c7 44 0d 00 7c 33 a2 ee 81 44 0d 00 20 a2 eb ?? ?? ?? ?? b5 8e 81 74 0d 00 3c ba 9e ?? ?? ?? ?? 81 74 0d 00 ?? ?? ?? ?? 66 f7 c3 7f ca 66 39 d8 89 bd}  //weight: 5, accuracy: Low
        $x_1_2 = "Ym.YjQA2e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Minix_SI_2147964367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Minix.SI!MTB"
        threat_id = "2147964367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Minix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Unpleasantly\\Uninstall\\tandklinikken\\unrig" ascii //weight: 2
        $x_1_2 = "sknskrifts\\tmmerproduktionerne\\plankevrket" ascii //weight: 1
        $x_1_3 = "Reinvestigating73\\Uninstall\\kursusforlbs" ascii //weight: 1
        $x_1_4 = "brankningernes" ascii //weight: 1
        $x_1_5 = "chamottelers.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Minix_SIW_2147964538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Minix.SIW!MTB"
        threat_id = "2147964538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Minix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "spedalske\\gracil\\inseam.ini" wide //weight: 2
        $x_1_2 = "loranskite\\falsedad.zip" wide //weight: 1
        $x_1_3 = "kunstvanding\\perisystole.txt" wide //weight: 1
        $x_1_4 = "Beregningsmssige34.ton" wide //weight: 1
        $x_1_5 = "temposkift\\Assuage217" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Minix_SNC_2147965574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Minix.SNC!MTB"
        threat_id = "2147965574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Minix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "detailvirksomheder testis behandlingsvirksomheder" ascii //weight: 1
        $x_1_2 = "miscript fniste" ascii //weight: 1
        $x_1_3 = "hoydenishness disclosive.exe" ascii //weight: 1
        $x_1_4 = "oasthouse ensrettende" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Minix_SNG_2147968418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Minix.SNG!MTB"
        threat_id = "2147968418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Minix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Afmytologiseringers" ascii //weight: 1
        $x_1_2 = "\\Bulter\\sanseverdeners.ini" ascii //weight: 1
        $x_1_3 = "\\dagtyve\\reserveret.exe" ascii //weight: 1
        $x_1_4 = "\\postevandet\\butteris.exe" ascii //weight: 1
        $x_1_5 = "\\Decimalvrdiernes249.zip" ascii //weight: 1
        $x_1_6 = "\\udgiftsfres.ini" ascii //weight: 1
        $x_1_7 = "Enneagynous.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

