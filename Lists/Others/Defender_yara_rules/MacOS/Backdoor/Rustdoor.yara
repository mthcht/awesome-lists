rule Backdoor_MacOS_Rustdoor_A_2147903499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Rustdoor.A!MTB"
        threat_id = "2147903499"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Rustdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "programsrc/persistence.rs/Users//Library/LaunchAgents.plistFailed" ascii //weight: 1
        $x_1_2 = "Launchctlsrc/http.rsgateway/tasktasks/uplo" ascii //weight: 1
        $x_1_3 = "lib.rslaunchctlunload-wFailed" ascii //weight: 1
        $x_1_4 = "hostname-commandtemp.ziptaskkilldownload" ascii //weight: 1
        $x_1_5 = "psshellcdmkdirrmrmdirsleepuploadbotkillError" ascii //weight: 1
        $x_1_6 = "pkill-15com.apple.dockpersistent-apps" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_MacOS_Rustdoor_B_2147903500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Rustdoor.B!MTB"
        threat_id = "2147903500"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Rustdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pkill-15com.apple.dockpersistent-apps" ascii //weight: 1
        $x_1_2 = "/tmp/com.apple.locksrc/cron.rs/cron/cron_asked/var/at/tabs/" ascii //weight: 1
        $x_1_3 = "lib.rslaunchctlunload-wFailed" ascii //weight: 1
        $x_1_4 = "defaults/.passwdhostname-commandtaskkilldownload" ascii //weight: 1
        $x_1_5 = "programsrc/persistence.rs/Users//Library/LaunchAgents.plistsrc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_MacOS_Rustdoor_C_2147914719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Rustdoor.C!MTB"
        threat_id = "2147914719"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Rustdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "commandtaskkilldownload" ascii //weight: 1
        $x_1_2 = "botkillparam" ascii //weight: 1
        $x_1_3 = "upload_filesrc/zipfile" ascii //weight: 1
        $x_1_4 = "lib.rslaunchctlunload-wFailed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_Rustdoor_D_2147914720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Rustdoor.D!MTB"
        threat_id = "2147914720"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Rustdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/.passwdfile.ziphostname-commandtaskkilldownload" ascii //weight: 1
        $x_1_2 = "grabfiles.rsgateway/registercheck_cron_asked" ascii //weight: 1
        $x_1_3 = "plistpkill-15com.apple.dockpersistent-apps" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_Rustdoor_E_2147921853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Rustdoor.E!MTB"
        threat_id = "2147921853"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Rustdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rc_remote_load_command" ascii //weight: 1
        $x_1_2 = "launch_inject" ascii //weight: 1
        $x_1_3 = "commandtaskkilldownload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

