rule Trojan_Win32_Siggen_GR_2147814963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Siggen.GR!MTB"
        threat_id = "2147814963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Siggen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c7 43 18 ff ff ff ff c7 43 28 ff ff ff ff c7 43 30 ff ff ff ff c7 43 48 28 81 40 00 c7 43 4c f0 72 40 00 8d b5 56 ff ff ff 8d 85 75 ff ff ff b1 01 eb 03}  //weight: 10, accuracy: High
        $x_10_2 = {88 45 ef 0f be 45 ef 89 45 f4 8b 45 10 31 45 f4 8b 45 f4 88 45 ef 8a 55 ef 8b 45 e4 88 10}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Siggen_AMTB_2147981271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Siggen!AMTB"
        threat_id = "2147981271"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Siggen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"%s\" /Create /TN \"NetProfileDiag\" /TR \"\\\"%s\\\" --stub-watch\"\\ /SC MINUTE /MO 3 /RU SYSTEM /RL HIGHEST /F" ascii //weight: 1
        $x_1_2 = "cmd.exe /c \"%s\" /Create /TN \"NetProfileDiag\" /TR \"\\\"%s\\\" --stub-watch\" /SC MINUTE /MO 3 /RU SYSTEM /RL HIGHEST /F" ascii //weight: 1
        $x_1_3 = "\"%s\" /Delete /TN \"NetProfileDiag\" /F" ascii //weight: 1
        $x_1_4 = "{\"machine_id\":\"%s\",\"install_id\":\"%s\",\"presence_url\":\"%s\",\"presence_key\":\"%s\",\"device_token\":\"%s\"," ascii //weight: 1
        $x_1_5 = "\"mm_path\":\"%s\",\"update_base\":\"%s\",\"exe_path\":\"%s\",\"exe_prev\":\"%s\",\"allow_rotate\":%d,\"critical_process\":%d}" ascii //weight: 1
        $x_1_6 = "schtasks.exe /Create /TN \"CertEnrollmentRepair\" /TR \"cmd.exe /c \\\"%s\\\"\" /SC ONCE /ST %s /RU SYSTEM /RL HIGHEST /F" ascii //weight: 1
        $x_1_7 = "schtasks.exe /Run /TN \"CertEnrollmentRepair\"" ascii //weight: 1
        $x_1_8 = "cmd.exe /c ping 127.0.0.1 -n 3 >nul & call \"%s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

