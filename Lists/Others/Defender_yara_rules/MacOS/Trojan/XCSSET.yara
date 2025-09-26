rule Trojan_MacOS_XCSSET_B_2147789300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCSSET.B"
        threat_id = "2147789300"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCSSET"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5f 54 74 43 43 [0-16] 64 [0-2] 57 65 62 53 6f 63 6b 65 74 31 30 57 53 52 65 73 70 6f 6e 73 65}  //weight: 1, accuracy: Low
        $x_1_2 = "d/Worker.swift" ascii //weight: 1
        $x_1_3 = {48 b8 50 61 67 65 2e 67 65 74 48 89 ?? ?? 48 b8 43 6f 6f 6b 69 65 73 ef}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_XCSSET_J_2147794885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCSSET.J"
        threat_id = "2147794885"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCSSET"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HaC80bwXscjqZ7KM6VOxULOB534" ascii //weight: 1
        $x_1_2 = "No writable apps were found and modded. Exiting." ascii //weight: 1
        $x_1_3 = "Resetting all cookies, payloads, cors targets" ascii //weight: 1
        $x_1_4 = "CSP Bypass disabled. Enabling" ascii //weight: 1
        $x_1_5 = "grep -q 'remote-debugging-port=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_XCSSET_AB_2147933668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCSSET.AB"
        threat_id = "2147933668"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCSSET"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "echo " wide //weight: 20
        $x_2_2 = "| xxd -p -r | xxd -p -r |" wide //weight: 2
        $x_2_3 = "| base64 -D | base64 -D |" wide //weight: 2
        $x_10_4 = "| sh >/dev/null 2>&1 &" wide //weight: 10
        $x_10_5 = "| sh ) >/dev/null 2>&1 &" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_2_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_XCSSET_AZ_2147933834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCSSET.AZ"
        threat_id = "2147933834"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCSSET"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sh -c" wide //weight: 1
        $x_1_2 = "bash -c" wide //weight: 1
        $x_5_3 = "grep -qF '.zshrc_aliases' ~/.zshrc || echo '[ -f $HOME/.zshrc_aliases ] && . $HOME/.zshrc_aliases' >> ~/.zshrc" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_XCSSET_ST_2147935106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCSSET.ST"
        threat_id = "2147935106"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCSSET"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "curl -fskL -d " wide //weight: 1
        $x_10_2 = {6f 00 73 00 3d 00 [0-32] 26 00 70 00 3d 00 78 00 63 00 6f 00 64 00 65 00 26 00 75 00 3d 00}  //weight: 10, accuracy: Low
        $x_10_3 = {6f 00 73 00 3d 00 [0-32] 26 00 70 00 3d 00 64 00 65 00 66 00 61 00 75 00 6c 00 74 00}  //weight: 10, accuracy: Low
        $x_1_4 = {68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 75 00 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_XCSSET_SC_2147935107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCSSET.SC"
        threat_id = "2147935107"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCSSET"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xprotect version 2>/dev/null" wide //weight: 1
        $x_1_2 = "XProtect.bundle/Contents/Info.plist CFBundleShortVersionString 2" wide //weight: 1
        $x_1_3 = "curl -fskL -d " wide //weight: 1
        $x_1_4 = "killall -9 osascript" wide //weight: 1
        $x_1_5 = "osacompile -o" wide //weight: 1
        $x_1_6 = "plutil -replace LSUIElement -bool YES" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_XCSSET_SD_2147935108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCSSET.SD"
        threat_id = "2147935108"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCSSET"
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

rule Trojan_MacOS_XCSSET_SE_2147935109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCSSET.SE"
        threat_id = "2147935109"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCSSET"
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

rule Trojan_MacOS_XCSSET_SF_2147935110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCSSET.SF"
        threat_id = "2147935110"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCSSET"
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

rule Trojan_MacOS_XCSSET_SG_2147935111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCSSET.SG"
        threat_id = "2147935111"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCSSET"
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

rule Trojan_MacOS_XCSSET_SH_2147935112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCSSET.SH"
        threat_id = "2147935112"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCSSET"
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

rule Trojan_MacOS_XCSSET_SI_2147935113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCSSET.SI"
        threat_id = "2147935113"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCSSET"
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

rule Trojan_MacOS_XCSSET_SJ_2147935114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCSSET.SJ"
        threat_id = "2147935114"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCSSET"
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

rule Trojan_MacOS_XCSSET_SK_2147935115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCSSET.SK"
        threat_id = "2147935115"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCSSET"
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

rule Trojan_MacOS_XCSSET_SZ_2147935617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCSSET.SZ"
        threat_id = "2147935617"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCSSET"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "51"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = "curl " wide //weight: 50
        $x_1_2 = {68 00 74 00 74 00 70 00 [0-16] 62 00 75 00 6c 00 6b 00 6e 00 61 00 6d 00 65 00 73 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 74 00 74 00 70 00 [0-16] 63 00 61 00 73 00 74 00 6c 00 65 00 6e 00 65 00 74 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_4 = {68 00 74 00 74 00 70 00 [0-16] 63 00 68 00 61 00 6f 00 70 00 69 00 6e 00 67 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_5 = {68 00 74 00 74 00 70 00 [0-16] 64 00 65 00 76 00 61 00 70 00 70 00 6c 00 65 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_6 = {68 00 74 00 74 00 70 00 [0-16] 67 00 69 00 67 00 61 00 63 00 65 00 6c 00 6c 00 73 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_7 = {68 00 74 00 74 00 70 00 [0-16] 69 00 74 00 6f 00 79 00 61 00 64 00 73 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_8 = {68 00 74 00 74 00 70 00 [0-16] 72 00 69 00 67 00 67 00 6c 00 65 00 6a 00 6f 00 79 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_9 = {68 00 74 00 74 00 70 00 [0-16] 72 00 75 00 74 00 6f 00 72 00 6e 00 65 00 74 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_10 = {68 00 74 00 74 00 70 00 [0-16] 73 00 69 00 67 00 6d 00 61 00 74 00 65 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_11 = {68 00 74 00 74 00 70 00 [0-16] 76 00 69 00 76 00 61 00 74 00 61 00 64 00 73 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_12 = {68 00 74 00 74 00 70 00 [0-16] 61 00 70 00 73 00 63 00 64 00 6e 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_13 = {68 00 74 00 74 00 70 00 [0-16] 6d 00 65 00 6c 00 6f 00 64 00 79 00 61 00 70 00 70 00 73 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_14 = {68 00 74 00 74 00 70 00 [0-16] 6d 00 6f 00 62 00 69 00 6c 00 65 00 63 00 64 00 6e 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_15 = {68 00 74 00 74 00 70 00 [0-16] 72 00 65 00 67 00 73 00 74 00 61 00 74 00 73 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_16 = {68 00 74 00 74 00 70 00 [0-16] 67 00 75 00 72 00 75 00 6d 00 61 00 64 00 65 00 73 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_17 = {68 00 74 00 74 00 70 00 [0-16] 6b 00 69 00 6e 00 6b 00 73 00 64 00 6f 00 63 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_18 = {68 00 74 00 74 00 70 00 [0-16] 6d 00 65 00 6c 00 69 00 6e 00 64 00 61 00 73 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_19 = {68 00 74 00 74 00 70 00 [0-16] 74 00 72 00 69 00 78 00 6d 00 61 00 74 00 65 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_20 = {68 00 74 00 74 00 70 00 [0-16] 66 00 69 00 67 00 6d 00 61 00 73 00 6f 00 6c 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_21 = {68 00 74 00 74 00 70 00 [0-16] 67 00 69 00 7a 00 6d 00 6f 00 64 00 6f 00 63 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_22 = {68 00 74 00 74 00 70 00 [0-16] 63 00 64 00 6e 00 74 00 6f 00 72 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_23 = {68 00 74 00 74 00 70 00 [0-16] 63 00 68 00 65 00 63 00 6b 00 63 00 64 00 6e 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_24 = {68 00 74 00 74 00 70 00 [0-16] 63 00 64 00 63 00 61 00 63 00 68 00 65 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_25 = {68 00 74 00 74 00 70 00 [0-16] 61 00 70 00 70 00 6c 00 65 00 63 00 64 00 6e 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_26 = {68 00 74 00 74 00 70 00 [0-16] 66 00 6c 00 6f 00 77 00 63 00 64 00 6e 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_27 = {68 00 74 00 74 00 70 00 [0-16] 65 00 6c 00 61 00 73 00 74 00 69 00 63 00 64 00 6e 00 73 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_28 = {68 00 74 00 74 00 70 00 [0-16] 72 00 75 00 62 00 6c 00 65 00 6e 00 65 00 74 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_29 = {68 00 74 00 74 00 70 00 [0-16] 66 00 69 00 78 00 6d 00 61 00 74 00 65 00 73 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_30 = {68 00 74 00 74 00 70 00 [0-16] 64 00 69 00 67 00 69 00 63 00 68 00 61 00 74 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_31 = {68 00 74 00 74 00 70 00 [0-16] 64 00 69 00 67 00 67 00 69 00 6d 00 61 00 78 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_32 = {68 00 74 00 74 00 70 00 [0-16] 66 00 69 00 67 00 6d 00 61 00 73 00 74 00 61 00 72 00 73 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_33 = {68 00 74 00 74 00 70 00 [0-16] 62 00 75 00 6c 00 6b 00 73 00 65 00 63 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_34 = {68 00 74 00 74 00 70 00 [0-16] 64 00 6f 00 62 00 65 00 74 00 72 00 69 00 78 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_35 = {68 00 74 00 74 00 70 00 [0-16] 66 00 69 00 67 00 6d 00 61 00 63 00 61 00 74 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_36 = {68 00 74 00 74 00 70 00 [0-16] 63 00 64 00 6e 00 72 00 6f 00 75 00 74 00 65 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_37 = {68 00 74 00 74 00 70 00 [0-16] 73 00 69 00 67 00 6d 00 61 00 6e 00 6f 00 77 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_38 = {68 00 74 00 74 00 70 00 [0-16] 6d 00 64 00 73 00 63 00 61 00 63 00 68 00 65 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_39 = {68 00 74 00 74 00 70 00 [0-16] 74 00 72 00 69 00 6e 00 69 00 74 00 79 00 73 00 6f 00 6c 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_40 = {68 00 74 00 74 00 70 00 [0-16] 76 00 65 00 72 00 69 00 66 00 79 00 73 00 69 00 67 00 6e 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_41 = {68 00 74 00 74 00 70 00 [0-16] 64 00 69 00 67 00 69 00 74 00 61 00 6c 00 63 00 64 00 6e 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_42 = {68 00 74 00 74 00 70 00 [0-16] 77 00 69 00 6e 00 64 00 73 00 65 00 63 00 75 00 72 00 65 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_43 = {68 00 74 00 74 00 70 00 [0-16] 64 00 6f 00 62 00 65 00 63 00 64 00 6e 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_44 = {68 00 74 00 74 00 70 00 [0-16] 6e 00 65 00 74 00 70 00 6c 00 61 00 6e 00 61 00 70 00 73 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_45 = {68 00 74 00 74 00 70 00 [0-16] 61 00 63 00 63 00 61 00 70 00 70 00 6c 00 65 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_46 = {68 00 74 00 74 00 70 00 [0-16] 63 00 64 00 6e 00 67 00 6c 00 6f 00 62 00 61 00 6c 00 2e 00 72 00 75 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_XCSSET_SB_2147935618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCSSET.SB"
        threat_id = "2147935618"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCSSET"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 75 00 72 00 6c 00 20 00 2d 00 6f 00 20 00 2f 00 74 00 6d 00 70 00 2f 00 [0-32] 20 00 2d 00 66 00 73 00 6b 00 4c 00 20 00 2d 00 64 00 20 00 70 00 3d 00 64 00 65 00 66 00 61 00 75 00 6c 00 74 00 26 00 75 00 3d 00 [0-32] 26 00 61 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_2 = {20 00 68 00 74 00 74 00 70 00 [0-32] 2e 00 72 00 75 00 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_XCSSET_BA_2147952334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCSSET.BA"
        threat_id = "2147952334"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCSSET"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "do shell script" wide //weight: 1
        $x_2_2 = {63 00 75 00 72 00 6c 00 20 00 2d 00 66 00 73 00 6b 00 4c 00 20 00 2d 00 6f 00 20 00 2f 00 74 00 6d 00 70 00 2f 00 [0-64] 68 00 74 00 74 00 70 00 [0-48] 2e 00 72 00 75 00 2f 00 [0-64] 26 00 26 00 20 00 6f 00 73 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 2f 00 74 00 6d 00 70 00}  //weight: 2, accuracy: Low
        $x_1_3 = "rm -f /tmp/" wide //weight: 1
        $x_1_4 = "end try" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

