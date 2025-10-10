rule Trojan_Win32_DarkKomet_DEA_2147760365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkKomet.DEA!MTB"
        threat_id = "2147760365"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 8b 45 ?? 69 c0 ?? ?? ?? ?? 99 be ?? ?? ?? ?? f7 fe 33 d2 8a 94 05 ?? ?? ?? ?? 33 ca 8b 45 ?? 69 c0 ?? ?? ?? ?? 99 be ?? ?? ?? ?? f7 fe 8b 55 ?? 88 0c 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkKomet_RT_2147809234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkKomet.RT!MTB"
        threat_id = "2147809234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "n9PwoaEl" ascii //weight: 1
        $x_1_2 = "]E_La{cQe;gpivkXmPo" ascii //weight: 1
        $x_1_3 = "XzbUDhCmxuSl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkKomet_RB_2147833959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkKomet.RB!MTB"
        threat_id = "2147833959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ATzQpBpmgyvSCMS" wide //weight: 1
        $x_1_2 = "rhvFoobcCL" wide //weight: 1
        $x_1_3 = "DhLJrg" wide //weight: 1
        $x_1_4 = "CnuBRtsIyA" wide //weight: 1
        $x_1_5 = "MsnomrcVdGiSjnq" wide //weight: 1
        $x_1_6 = "8blxx.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkKomet_MB_2147836828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkKomet.MB!MTB"
        threat_id = "2147836828"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/H*8|P8T/ T/*vTX36X8fPT/fHTb3]%P8T/bYT" ascii //weight: 2
        $x_2_2 = "FILECOPY ( $_QOAL , $_XOL1 , 1 + 8 )" ascii //weight: 2
        $x_2_3 = "_GRPL = MOUSEGETPOS ( 0 ) & _Q9R6" ascii //weight: 2
        $x_2_4 = "FILEDELETE ( $_YSMP )" ascii //weight: 2
        $x_2_5 = "$_X0DN [ 2 ]" ascii //weight: 2
        $x_2_6 = "1000 * ( ( 3600 * $_RFUQ ) + ( 60 * $_JZBN ) + $_O99M )" ascii //weight: 2
        $x_2_7 = "STRINGRIGHT ( _Q9R6 (" ascii //weight: 2
        $x_2_8 = "RUN ( @COMSPEC & _Q9R6" ascii //weight: 2
        $x_2_9 = "_AHY0 = @TEMPDIR & _Q9R6" ascii //weight: 2
        $x_2_10 = "DLLOPEN ( _Q9R6" ascii //weight: 2
        $x_2_11 = "STRINGREPLACE ( $CMDLINERAW , CHR (" ascii //weight: 2
        $x_2_12 = "IF ( FILEEXISTS ( $_QEAF ) )" ascii //weight: 2
        $x_2_13 = "W14*]+X" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkKomet_RA_2147838989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkKomet.RA!MTB"
        threat_id = "2147838989"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Administrador\\Escritorio\\SUPER\\STUB\\olalalallalalal.vbp" wide //weight: 1
        $x_1_2 = "Escritorio\\TM.exe" ascii //weight: 1
        $x_1_3 = "Archivos de programa\\NTCore\\Explorer Suite\\Extensions\\CFF Explorer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkKomet_MBHL_2147852451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkKomet.MBHL!MTB"
        threat_id = "2147852451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 97 4c 00 0b f0 30 01 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 01 00 e9 00 00 00 4c 93 4c 00 30 95 4c 00 28 15 40 00 78}  //weight: 1, accuracy: High
        $x_1_2 = {48 da 41 00 0f f3 32 00 00 ff ff ff 08 00 00 00 01 00 00 00 04 00 04 00 e9 00 00 00 b8 d7 41 00 f4 e2 41 00 60 28 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_DarkKomet_SA_2147890563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkKomet.SA!MTB"
        threat_id = "2147890563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 4c 24 ?? c1 e8 ?? 40 89 44 24 ?? 8d 9b ?? ?? ?? ?? 0f b6 46 ?? 8d 3c 31 32 03 88 07 0f b6 46 ?? 32 43 ?? 88 42}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkKomet_GVA_2147954811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkKomet.GVA!MTB"
        threat_id = "2147954811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f d8 c0 66 0f e5 d1 66 0f dc f0 66 0f f5 ff 66 0f 76 e0 0f fa fb 0f e1 c8 0f 71 f0 03 66 0f d5 c3 66 0f 71 d2 cc 31 34 24 66 0f 69 f1 66 0f fe c9 66 0f fc e8 66 0f e9 ec 0f db c7 66 0f 6a f2 eb 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

