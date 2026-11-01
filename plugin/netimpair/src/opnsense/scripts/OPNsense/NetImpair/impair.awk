# Usage: awk -f impair.awk netimpair.conf dnctl.conf
# netimpair.conf lines: <pipe number> <delay ms or -> <loss fraction>
#
# The options go right after "config": dnctl takes every word after
# "type fq_codel|fq_pie" or "codel|pie" as a scheduler/AQM parameter, so
# anything added at the end of such a line would be ignored.
FNR == NR {
    if (NF == 3) { delay[$1] = $2; loss[$1] = $3 }
    next
}
$1 == "pipe" && $3 == "config" && ($2 in loss) {
    add = ""
    if (delay[$2] != "-") {
        gsub(/ delay [0-9]+/, "")
        add = " delay " delay[$2]
    }
    if (loss[$2] + 0 > 0) {
        add = add " plr " loss[$2]
    }
    sub(/ config/, " config" add)
}
# Loss is kept per queue in dummynet, so traffic a shaper rule sends to a
# queue of the pipe skips the pipe's own plr: give the queue the same loss.
# (The delay belongs to the pipe's link, which queued traffic also crosses.)
$1 == "queue" && $3 == "config" && $4 == "pipe" && ($5 in loss) && loss[$5] + 0 > 0 {
    sub(/ config/, " config plr " loss[$5])
}
{ print }
