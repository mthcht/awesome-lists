rule Trojan_Win32_FudRat_AFU_2147975377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FudRat.AFU!MTB"
        threat_id = "2147975377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FudRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files have been encrypted" ascii //weight: 1
        $x_1_2 = "Contact the operator to recover them" ascii //weight: 1
        $x_1_3 = "cryptowall: encrypted" ascii //weight: 1
        $x_1_4 = "usage: .cryptowall <dir>" ascii //weight: 1
        $x_1_5 = "cryptowall running" ascii //weight: 1
        $x_1_6 = "imploding" ascii //weight: 1
        $x_1_7 = "uninstalling - goodbye" ascii //weight: 1
        $x_1_8 = "void engaged (permanent until .unvoid)" ascii //weight: 1
        $x_1_9 = "void disengaged (restores on next reboot)" ascii //weight: 1
        $x_1_10 = "grab complete -> #passwords / #cookies" ascii //weight: 1
        $x_1_11 = "mic loop started" ascii //weight: 1
        $x_1_12 = "photo loop started (every 5s) -> #recordings" ascii //weight: 1
        $x_1_13 = "screen stream started" ascii //weight: 1
        $x_1_14 = "locked - scheduled for delete on reboot" ascii //weight: 1
        $x_1_15 = "usage: .decrypt <path.enc>" ascii //weight: 1
        $x_1_16 = "usage: .delfile <path>" ascii //weight: 1
        $x_1_17 = "usage: .dlchunk <path>  (exfil large file in chunks)" ascii //weight: 1
        $x_1_18 = "usage: attach file in Discord + .upload [save-as]  OR  .upload <url>" ascii //weight: 1
        $x_1_19 = "start keylogger" ascii //weight: 1
        $x_1_20 = "stop keylogger + send log" ascii //weight: 1
        $x_1_21 = "usage: .key <text> or .key ctrl+f4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

