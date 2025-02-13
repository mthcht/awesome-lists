rule Trojan_Win32_GenCBL_SIB_2147780373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GenCBL.SIB!MTB"
        threat_id = "2147780373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GenCBL"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "itdownload.dll" ascii //weight: 20
        $x_20_2 = ".com/pwrap.exe" ascii //weight: 20
        $x_20_3 = "App Manager\\App Manager.exe" ascii //weight: 20
        $x_20_4 = "App Manager\\pwrap.exe" ascii //weight: 20
        $x_1_5 = "itd_cancel" ascii //weight: 1
        $x_1_6 = "itd_clearfiles" ascii //weight: 1
        $x_1_7 = "itd_downloadfile" ascii //weight: 1
        $x_1_8 = "itd_getresultlen" ascii //weight: 1
        $x_1_9 = "itd_getresultstring" ascii //weight: 1
        $x_1_10 = "itd_initui" ascii //weight: 1
        $x_1_11 = "itd_loadstrings" ascii //weight: 1
        $x_1_12 = "itd_setoption" ascii //weight: 1
        $x_1_13 = "itd_getfilesize" ascii //weight: 1
        $x_1_14 = "itd_getstring" ascii //weight: 1
        $x_1_15 = "itd_getoption" ascii //weight: 1
        $x_1_16 = "itd_setstring" ascii //weight: 1
        $x_1_17 = "itd_addfile" ascii //weight: 1
        $x_1_18 = "itd_addmirror" ascii //weight: 1
        $x_1_19 = "itd_addfilesize" ascii //weight: 1
        $x_1_20 = "itd_downloadfiles" ascii //weight: 1
        $x_1_21 = "itd_filecount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 15 of ($x_1_*))) or
            ((3 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_GenCBL_SIBA_2147781940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GenCBL.SIBA!MTB"
        threat_id = "2147781940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GenCBL"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "service.exe" ascii //weight: 1
        $x_1_2 = "%APPDATA%\\service.exe" ascii //weight: 1
        $x_1_3 = "/C schtasks /create /tn MyApp /tr %APPDATA%\\service.exe /st 00:00 /du 9999:59 /sc daily /ri 1 /f" ascii //weight: 1
        $x_1_4 = "libgcc_s_dw2-1.dll" ascii //weight: 1
        $x_1_5 = "libgcj-16.dll" ascii //weight: 1
        $x_1_6 = "__register_frame_info" ascii //weight: 1
        $x_1_7 = "__deregister_frame_info" ascii //weight: 1
        $x_1_8 = "cmd.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_GenCBL_AVY_2147794587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GenCBL.AVY!MTB"
        threat_id = "2147794587"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GenCBL"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BenQ Zowie XL2411P 24" ascii //weight: 1
        $x_1_2 = "210907122320" ascii //weight: 1
        $x_1_3 = "310908122320" ascii //weight: 1
        $x_1_4 = "Greater Manchester" ascii //weight: 1
        $x_1_5 = "New Jersey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GenCBL_AYG_2147798771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GenCBL.AYG!MTB"
        threat_id = "2147798771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GenCBL"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Intel Xeon Scalable Silver 3rd Gen 4314" ascii //weight: 1
        $x_1_2 = "MSI GF65P" ascii //weight: 1
        $x_1_3 = "210923113846Z" ascii //weight: 1
        $x_1_4 = "310924113846Z02100" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GenCBL_PACU_2147900457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GenCBL.PACU!MTB"
        threat_id = "2147900457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GenCBL"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 f6 d6 68 ac 1c 01 9e 41 80 f6 27 41 d0 ce 41 fe ce 41 80 f6 19 45 32 de 48 81 ee 02 00 00 00 66 44 89 36}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

