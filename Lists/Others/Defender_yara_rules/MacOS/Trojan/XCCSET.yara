rule Trojan_MacOS_XCCSET_ST_2147933514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCCSET.ST"
        threat_id = "2147933514"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCCSET"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "echo " wide //weight: 1
        $x_1_2 = "curl -fskL -d " wide //weight: 1
        $x_1_3 = "os=$(uname -s)&p=" wide //weight: 1
        $x_1_4 = {68 00 74 00 74 00 70 00 [0-32] 2e 00 72 00 75 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_5 = "| sh >/dev/null 2>&1 &" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_XCCSET_SD_2147934713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCCSET.SD"
        threat_id = "2147934713"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCCSET"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "ioreg -k IOPlatformSerialNumber | grep IOPlatformSerialNumber | cut -w -f5 | xargs) 2" wide //weight: 4
        $x_3_2 = "whoami" wide //weight: 3
        $x_3_3 = {73 00 65 00 72 00 69 00 61 00 6c 00 4e 00 75 00 6d 00 62 00 65 00 72 00 20 00 [0-48] 20 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 4e 00 61 00 6d 00 65 00 20 00 [0-48] 20 00 6d 00 65 00 73 00 73 00 61 00 67 00 65 00}  //weight: 3, accuracy: Low
        $x_3_4 = "curl -fksL -m" wide //weight: 3
        $x_1_5 = "xxd -p -c0|xxd -p -r" wide //weight: 1
        $x_1_6 = "xxd -p|xxd -p -r" wide //weight: 1
        $x_1_7 = "base64|base64 -D" wide //weight: 1
        $x_1_8 = "base64|base64 --decode" wide //weight: 1
        $x_3_9 = {63 00 75 00 72 00 6c 00 20 00 2d 00 66 00 73 00 6b 00 4c 00 20 00 2d 00 64 00 20 00 [0-48] 70 00 3d 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 4 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_XCCSET_SE_2147934714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCCSET.SE"
        threat_id = "2147934714"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCCSET"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "ioreg -k IOPlatformSerialNumber | grep IOPlatformSerialNumber | cut -w -f5 | xargs) 2" wide //weight: 2
        $x_2_2 = "whoami" wide //weight: 2
        $x_2_3 = {73 00 65 00 72 00 69 00 61 00 6c 00 4e 00 75 00 6d 00 62 00 65 00 72 00 20 00 [0-48] 20 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 4e 00 61 00 6d 00 65 00 20 00 [0-48] 20 00 6d 00 65 00 73 00 73 00 61 00 67 00 65 00}  //weight: 2, accuracy: Low
        $x_2_4 = "do shell script (" wide //weight: 2
        $x_2_5 = "curl -fksL -m" wide //weight: 2
        $x_2_6 = "open -Wgna" wide //weight: 2
        $x_2_7 = "open -gna" wide //weight: 2
        $x_2_8 = "mdfind kMDItemCFBundleIdentifier =" wide //weight: 2
        $x_1_9 = "ru.keepcoder.Telegram" wide //weight: 1
        $x_1_10 = "ps aux | grep -v grep | grep -wci" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_XCCSET_SF_2147934715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCCSET.SF"
        threat_id = "2147934715"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCCSET"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ioreg -k IOPlatformSerialNumber | grep IOPlatformSerialNumber | cut -w -f5 | xargs) 2" wide //weight: 1
        $x_1_2 = "whoami" wide //weight: 1
        $x_1_3 = {73 00 65 00 72 00 69 00 61 00 6c 00 4e 00 75 00 6d 00 62 00 65 00 72 00 20 00 [0-48] 20 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 4e 00 61 00 6d 00 65 00 20 00 [0-48] 20 00 6d 00 65 00 73 00 73 00 61 00 67 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "curl -fksL -m" wide //weight: 1
        $x_1_5 = "(du -sm" wide //weight: 1
        $x_1_6 = "/dev/null || echo 0) | cut -f1" wide //weight: 1
        $x_1_7 = "upload" wide //weight: 1
        $x_1_8 = "urlencode" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_XCCSET_SG_2147934716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCCSET.SG"
        threat_id = "2147934716"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCCSET"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ioreg -k IOPlatformSerialNumber | grep IOPlatformSerialNumber | cut -w -f5 | xargs) 2" wide //weight: 1
        $x_1_2 = "whoami" wide //weight: 1
        $x_1_3 = {73 00 65 00 72 00 69 00 61 00 6c 00 4e 00 75 00 6d 00 62 00 65 00 72 00 20 00 [0-48] 20 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 4e 00 61 00 6d 00 65 00 20 00 [0-48] 20 00 6d 00 65 00 73 00 73 00 61 00 67 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "curl -fksL -m" wide //weight: 1
        $x_1_5 = "ps aux | grep -v grep | grep -wci" wide //weight: 1
        $x_1_6 = "osacompile -x -e " wide //weight: 1
        $x_1_7 = "plutil -replace LSUIElement -bool YES" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_XCCSET_SH_2147934717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCCSET.SH"
        threat_id = "2147934717"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCCSET"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ioreg -k IOPlatformSerialNumber | grep IOPlatformSerialNumber | cut -w -f5 | xargs) 2" wide //weight: 1
        $x_1_2 = "whoami" wide //weight: 1
        $x_1_3 = {73 00 65 00 72 00 69 00 61 00 6c 00 4e 00 75 00 6d 00 62 00 65 00 72 00 20 00 [0-48] 20 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 4e 00 61 00 6d 00 65 00 20 00 [0-48] 20 00 6d 00 65 00 73 00 73 00 61 00 67 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "curl -fksL -m" wide //weight: 1
        $x_1_5 = "/Library/Application Support/Firefox/Profiles/*/prefs.js|firefox_extensions" wide //weight: 1
        $x_1_6 = "/Library/Application Support/Microsoft Edge/*/Extensions/*/manifest.json|edge_extensions" wide //weight: 1
        $x_1_7 = "urlencode" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_XCCSET_SI_2147934718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCCSET.SI"
        threat_id = "2147934718"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCCSET"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "osascript -e" wide //weight: 1
        $x_1_2 = "ioreg -k IOPlatformSerialNumber | grep IOPlatformSerialNumber | cut -w -f5 | xargs) 2" wide //weight: 1
        $x_1_3 = "whoami" wide //weight: 1
        $x_1_4 = {73 00 65 00 72 00 69 00 61 00 6c 00 4e 00 75 00 6d 00 62 00 65 00 72 00 20 00 [0-48] 20 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 4e 00 61 00 6d 00 65 00 20 00 [0-48] 20 00 6d 00 65 00 73 00 73 00 61 00 67 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = "do shell script (" wide //weight: 1
        $x_1_6 = "curl -fksL -m" wide //weight: 1
        $x_1_7 = {68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 75 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_8 = "MAX_UPLOAD_FILESIZE" wide //weight: 1
        $x_1_9 = "urlencode" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_XCCSET_SJ_2147934719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCCSET.SJ"
        threat_id = "2147934719"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCCSET"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ioreg -k IOPlatformSerialNumber | grep IOPlatformSerialNumber | cut -w -f5 | xargs) 2" wide //weight: 1
        $x_1_2 = "whoami" wide //weight: 1
        $x_1_3 = {73 00 65 00 72 00 69 00 61 00 6c 00 4e 00 75 00 6d 00 62 00 65 00 72 00 20 00 [0-48] 20 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 4e 00 61 00 6d 00 65 00 20 00 [0-48] 20 00 6d 00 65 00 73 00 73 00 61 00 67 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "curl -fksL -m" wide //weight: 1
        $x_1_5 = "codesign --force --deep -s " wide //weight: 1
        $x_1_6 = "chmod +x " wide //weight: 1
        $x_1_7 = {63 00 68 00 6d 00 6f 00 64 00 20 00 30 00 30 00 30 00 20 00 [0-48] 2f 00 4c 00 69 00 62 00 72 00 61 00 72 00 79 00 2f 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 2f 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 55 00 70 00 64 00 61 00 74 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_XCCSET_SK_2147934720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCCSET.SK"
        threat_id = "2147934720"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCCSET"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ioreg -k IOPlatformSerialNumber | grep IOPlatformSerialNumber | cut -w -f5 | xargs) 2" wide //weight: 1
        $x_1_2 = "whoami" wide //weight: 1
        $x_1_3 = {73 00 65 00 72 00 69 00 61 00 6c 00 4e 00 75 00 6d 00 62 00 65 00 72 00 20 00 [0-48] 20 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 4e 00 61 00 6d 00 65 00 20 00 [0-48] 20 00 6d 00 65 00 73 00 73 00 61 00 67 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "do shell script (" wide //weight: 1
        $x_1_5 = "curl -fksL -m" wide //weight: 1
        $x_1_6 = "project.pbxproj" wide //weight: 1
        $x_1_7 = "perl -ni -e" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

