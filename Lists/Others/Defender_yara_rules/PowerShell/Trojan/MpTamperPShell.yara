rule Trojan_PowerShell_MpTamperPShell_HE_2147904652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/MpTamperPShell.HE"
        threat_id = "2147904652"
        type = "Trojan"
        platform = "PowerShell: "
        family = "MpTamperPShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "401"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "set-mppreference -force" wide //weight: 100
        $x_100_2 = "if(!$command.parameters.keys.contains($propertyname))" wide //weight: 100
        $x_100_3 = "$_.fullyqualifiederrorid -like '*0x800106ba*'" wide //weight: 100
        $x_100_4 = "defender service (windefend) is not running. try to enable it (revert) and re-run this?" wide //weight: 100
        $x_1_5 = "disableioavprotection" wide //weight: 1
        $x_1_6 = "disablerestorepoint" wide //weight: 1
        $x_1_7 = "puaprotection" wide //weight: 1
        $x_1_8 = "disableremovabledrivescanning" wide //weight: 1
        $x_1_9 = "disablecatchupquickscan" wide //weight: 1
        $x_1_10 = "disableblockatfirstseen" wide //weight: 1
        $x_1_11 = "disableautoexclusions" wide //weight: 1
        $x_1_12 = "disableprivacymode" wide //weight: 1
        $x_1_13 = "disableintrusionpreventionsystem" wide //weight: 1
        $x_1_14 = "disablebehaviormonitoring" wide //weight: 1
        $x_1_15 = "disablerealtimemonitoring" wide //weight: 1
        $x_1_16 = "disablescriptscanning" wide //weight: 1
        $x_1_17 = "disablearchivescanning" wide //weight: 1
        $x_1_18 = "disableemailscanning" wide //weight: 1
        $x_1_19 = "disablescanningmappednetworkdrivesforfullscan" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_PowerShell_MpTamperPShell_HF_2147904653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/MpTamperPShell.HF"
        threat_id = "2147904653"
        type = "Trojan"
        platform = "PowerShell: "
        family = "MpTamperPShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$scheduleservice = new-object -comobject schedule.service).connect();" wide //weight: 1
        $x_1_2 = "$scheduleservice.getfolder('\\').gettask($taskname).runex($null, 0, 0, $trustedinstallername)" wide //weight: 1
        $x_1_3 = "out-file $batchfile -encoding ascii; $taskname = 'privacy.sexy invoke';" wide //weight: 1
        $x_1_4 = "register-scheduledtask -taskname $taskname -action $taskaction -settings $settings -force -erroraction stop" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

