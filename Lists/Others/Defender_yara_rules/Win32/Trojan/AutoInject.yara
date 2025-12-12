rule Trojan_Win32_AutoInject_AE_2147902678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoInject.AE!MTB"
        threat_id = "2147902678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "STRINGREPLACE" ascii //weight: 1
        $x_1_2 = "STRINGRIGHT ( \"FBlyBiEyCqOwlTD24HDntVvyXlW0Yimib3S7y0iz2CNZgkanKV17TOwUfXLqvOKueFusaFDdzdv0gGrLl\"" ascii //weight: 1
        $x_1_3 = "WINACTIVE ( \"H15GXGEwcNj87NtSLAoN7iei0EojDOzDi3OM1htzpx4Xb584cRfnTcGzWXQrr\" )" ascii //weight: 1
        $x_1_4 = "SHELLEXECUTE ( @AUTOITEXE" ascii //weight: 1
        $x_1_5 = "WINEXISTS ( \"mBJqGuZvjQc3EMLJ3kD7BROqNRFUNg1b9E8sQYlFL\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoInject_AG_2147903358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoInject.AG!MTB"
        threat_id = "2147903358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FOR $OCIWEWXJU = 1 TO ( STRINGLEN ( $YYHBOZMPR ) + -4 )" ascii //weight: 1
        $x_1_2 = "SHELLEXECUTE ( @WORKINGDIR & CHR ( 92 ) & $QWPCNHIUI & CHR ( 92 ) & $WVPUALOCQ )" ascii //weight: 1
        $x_1_3 = "MVCAXNKLH ( $ZONVRDHZH [ 0 ] , $ZONVRDHZH [ $GRBPUPKWO ] )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoInject_CCHV_2147904394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoInject.CCHV!MTB"
        threat_id = "2147904394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "115?109?122?118?109?116?59?58" ascii //weight: 1
        $x_1_2 = "120?124?122" ascii //weight: 1
        $x_1_3 = "94?113?122?124?125?105?116?73?116?116?119?107" ascii //weight: 1
        $x_1_4 = "108?127?119?122?108" ascii //weight: 1
        $x_1_5 = "125?123?109?122?59?58" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoInject_AS_2147907579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoInject.AS!MTB"
        threat_id = "2147907579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-16] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-16] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-16] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-16] 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {46 00 49 00 4c 00 45 00 52 00 45 00 41 00 44 00 20 00 28 00 20 00 46 00 49 00 4c 00 45 00 4f 00 50 00 45 00 4e 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-14] 22 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {46 49 4c 45 52 45 41 44 20 28 20 46 49 4c 45 4f 50 45 4e 20 28 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-14] 22 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = "EXECUTE ( \"BinaryLen\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_AutoInject_SZ_2147909031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoInject.SZ!MTB"
        threat_id = "2147909031"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = "& \"(S\" & \"t\" & \"r\" & \"i\" & \"n\" & \"g\" & \"R\" & \"e\" & \"p\" & \"l\" & \"a\" & \"c\" & \"e\" &" ascii //weight: 1
        $x_1_4 = "EXECUTE ( \"F\" & \"i\" & \"l\" & \"e\" & \"R\" & \"e\" & \"a\" & \"d\" &" ascii //weight: 1
        $x_1_5 = "& \"@t\" & \"e\" & \"m\" & \"p\" & \"d\" & \"i\" & \"r &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_AutoInject_CCJB_2147921020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoInject.CCJB!MTB"
        threat_id = "2147921020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "b60AB0CCCy60AB0CCCt60AB0CCCe60AB0CCC[60AB0CCC" ascii //weight: 1
        $x_1_2 = "k60AB0CCCe60AB0CCCr60AB0CCCn60AB0CCCe60AB0CCCl60AB0CCC360AB0CCC260AB0CCC.60AB0CCCd60AB0CCCl60AB0CCCl60AB0CCC" ascii //weight: 1
        $x_1_3 = "u60AB0CCCs60AB0CCCe60AB0CCCr60AB0CCC360AB0CCC260AB0CCC.60AB0CCCd60AB0CCCl60AB0CCCl60AB0CCC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoInject_CCJC_2147921090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoInject.CCJC!MTB"
        threat_id = "2147921090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SLEEP ( 500 )" ascii //weight: 1
        $x_5_2 = "--kiosk --edge-kiosk-type=fullscreen --no-first-run --disable-features=TranslateUI" ascii //weight: 5
        $x_5_3 = "--kiosk --disable-features=TranslateUI --disable-infobars --no-first-run" ascii //weight: 5
        $x_1_4 = "--disable-popup-blocking --disable-extensions --no-default-browser-check --app=" ascii //weight: 1
        $x_1_5 = "$PRIMARYBROWSER = \"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" ascii //weight: 1
        $x_1_6 = "{ESC}\" , \"IgnoreKey" ascii //weight: 1
        $x_1_7 = "{F11}\" , \"IgnoreKey" ascii //weight: 1
        $x_1_8 = "SLEEP ( 100 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoInject_SPJD_2147921757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoInject.SPJD!MTB"
        threat_id = "2147921757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "k7IfgcdZxe7IfgcdZxr7IfgcdZxn7IfgcdZxe7IfgcdZxl7IfgcdZx37IfgcdZx27IfgcdZx.7IfgcdZxd7IfgcdZxl7IfgcdZxl7IfgcdZx" ascii //weight: 2
        $x_1_2 = "V7IfgcdZxi7IfgcdZxr7IfgcdZxt7IfgcdZxu7IfgcdZxa7IfgcdZxl7IfgcdZxP7IfgcdZxr7IfgcdZxo7IfgcdZxt7IfgcdZxe7IfgcdZxc7IfgcdZxt7IfgcdZx" ascii //weight: 1
        $x_1_3 = "u7IfgcdZxs7IfgcdZxe7IfgcdZxr7IfgcdZx37IfgcdZx27IfgcdZx.7IfgcdZxd7IfgcdZxl7IfgcdZxl7IfgcdZx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoInject_CCJD_2147921780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoInject.CCJD!MTB"
        threat_id = "2147921780"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "d9T0qwT5Ad9T0qwT5Dd9T0qwT5Od9T0qwT5Dd9T0qwT5Bd9T0qwT5.d9T0qwT5Sd9T0qwT5td9T0qwT5rd9T0qwT5ed9T0qwT5ad9T0qwT5md9T0qwT5" ascii //weight: 2
        $x_1_2 = "kd9T0qwT5ed9T0qwT5rd9T0qwT5nd9T0qwT5ed9T0qwT5ld9T0qwT53d9T0qwT52d9T0qwT5" ascii //weight: 1
        $x_1_3 = "Vd9T0qwT5id9T0qwT5rd9T0qwT5td9T0qwT5ud9T0qwT5ad9T0qwT5ld9T0qwT5Pd9T0qwT5rd9T0qwT5od9T0qwT5td9T0qwT5ed9T0qwT5cd9T0qwT5td9T0qwT5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoInject_C_2147923359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoInject.C!MTB"
        threat_id = "2147923359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 36 56 a6 df 30 77 1c 5f 2c ca 62 22 c9 ec 35 7e c6 63 63 dd 4c 49 93 4f 65 5c e7 e4 b2 fb f6 be 1f e7 c1 f5 76 81 12 b2 5b 16 a2 9d dc d9 41 d7 eb 43 fd e8 ec a8 65 b9 85 49 82 2a e9 d5 1e e7 0b 13 5a c8 d4 4c bb 0f ed e8 93 9b 5a 39 8a 9a 9c c7 84 63 25 8f a0 dd 77 9d 7e 68 81 df 8f 3d 77 87 73 6e 2d a1 7d 06 9b 19 a1 bc 51 21 16 cd 5f 5d d9 b5 15 0d 6a fb eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoInject_C_2147923359_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoInject.C!MTB"
        threat_id = "2147923359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 00 54 00 52 00 49 00 4e 00 47 00 20 00 28 00 20 00 48 00 45 00 58 00 20 00 28 00 20 00 24 00 [0-15] 20 00 5b 00 20 00 24 00 49 00 20 00 5d 00 20 00 2c 00 20 00 32 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {53 54 52 49 4e 47 20 28 20 48 45 58 20 28 20 24 [0-15] 20 5b 20 24 49 20 5d 20 2c 20 32 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {42 00 49 00 4e 00 41 00 52 00 59 00 54 00 4f 00 53 00 54 00 52 00 49 00 4e 00 47 00 20 00 28 00 20 00 22 00 30 00 78 00 22 00 20 00 26 00 20 00 24 00 [0-15] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {42 49 4e 41 52 59 54 4f 53 54 52 49 4e 47 20 28 20 22 30 78 22 20 26 20 24 [0-15] 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 43 00 52 00 45 00 41 00 54 00 45 00 20 00 28 00 20 00 22 00 62 00 79 00 74 00 65 00 5b 00 22 00 20 00 26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-15] 20 00 29 00 20 00 26 00 20 00 22 00 5d 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {44 4c 4c 53 54 52 55 43 54 43 52 45 41 54 45 20 28 20 22 62 79 74 65 5b 22 20 26 20 42 49 4e 41 52 59 4c 45 4e 20 28 20 24 [0-15] 20 29 20 26 20 22 5d 22 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = "DLLCALL ( \"kernel32.dll\" , \"BOOL\" , \"VirtualProtect\" , \"ptr\" ," ascii //weight: 1
        $x_1_8 = {44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 53 00 45 00 54 00 44 00 41 00 54 00 41 00 20 00 28 00 20 00 24 00 [0-15] 20 00 2c 00 20 00 31 00 20 00 2c 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 54 00 4f 00 53 00 54 00 52 00 49 00 4e 00 47 00 20 00 28 00 20 00 22 00 30 00 78 00 22 00 20 00 26 00 20 00 24 00 [0-15] 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_9 = {44 4c 4c 53 54 52 55 43 54 53 45 54 44 41 54 41 20 28 20 24 [0-15] 20 2c 20 31 20 2c 20 42 49 4e 41 52 59 54 4f 53 54 52 49 4e 47 20 28 20 22 30 78 22 20 26 20 24 [0-15] 20 29 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_AutoInject_NRA_2147959368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoInject.NRA!MTB"
        threat_id = "2147959368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = "EXECUTE ( \"D\" & \"ll\" & \"Ca\" & \"ll\" & \"A\" & \"ddr\" & \"e\" & \"ss" ascii //weight: 1
        $x_1_4 = "&= EXECUTE ( \"As\" & \"c(Str\" & \"ingMi\" & \"d" ascii //weight: 1
        $x_1_5 = {52 00 45 00 54 00 55 00 52 00 4e 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 53 00 74 00 72 00 69 00 22 00 20 00 26 00 20 00 22 00 6e 00 67 00 54 00 22 00 20 00 26 00 20 00 22 00 72 00 69 00 6d 00 52 00 22 00 20 00 26 00 20 00 22 00 69 00 67 00 68 00 74 00 28 00 24 00 [0-31] 2c 00 20 00 31 00 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {52 45 54 55 52 4e 20 45 58 45 43 55 54 45 20 28 20 22 53 74 72 69 22 20 26 20 22 6e 67 54 22 20 26 20 22 72 69 6d 52 22 20 26 20 22 69 67 68 74 28 24 [0-31] 2c 20 31 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 4d 00 22 00 20 00 26 00 20 00 22 00 6f 00 64 00 28 00 [0-31] 28 00 24 00 [0-31] 29 00 20 00 20 00 2d 00 20 00 [0-31] 28 00 53 00 74 00 72 00 69 00 6e 00 67 00 4d 00 69 00 64 00 28 00 24 00 [0-31] 2c 00 20 00 4d 00 6f 00 64 00 28 00 24 00 [0-31] 20 00 2d 00 20 00 31 00 2c 00 20 00 24 00 [0-31] 29 00 20 00 2b 00 20 00 31 00 2c 00 20 00 31 00 29 00 29 00 2c 00 20 00 32 00 35 00 36 00 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {45 58 45 43 55 54 45 20 28 20 22 4d 22 20 26 20 22 6f 64 28 [0-31] 28 24 [0-31] 29 20 20 2d 20 [0-31] 28 53 74 72 69 6e 67 4d 69 64 28 24 [0-31] 2c 20 4d 6f 64 28 24 [0-31] 20 2d 20 31 2c 20 24 [0-31] 29 20 2b 20 31 2c 20 31 29 29 2c 20 32 35 36 29 22 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

