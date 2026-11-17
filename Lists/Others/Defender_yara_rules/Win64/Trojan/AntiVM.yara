rule Trojan_Win64_AntiVM_NV_2147977665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AntiVM.NV!MTB"
        threat_id = "2147977665"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AntiVM"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii //weight: 1
        $x_2_3 = "ncrthost.dll" ascii //weight: 2
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "vboxservice.exe" ascii //weight: 1
        $x_1_6 = "vmwareuser.exe" ascii //weight: 1
        $x_1_7 = "safemode-encrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AntiVM_AP_2147982226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AntiVM.AP!MTB"
        threat_id = "2147982226"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AntiVM"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vmbypass.token" ascii //weight: 2
        $x_5_2 = "===== AIoTUpdater v%s started" ascii //weight: 5
        $x_3_3 = "NOT writing update_210.dat (will retry next run)" ascii //weight: 3
        $x_4_4 = "install_id.dat" ascii //weight: 4
        $x_6_5 = "updater_200.log" ascii //weight: 6
        $x_10_6 = "Global\\AIOT_Updater_200_Mutex" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

