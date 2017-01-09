# H.323 - Voice over IP.
# Pattern attributes: ok veryfast fast
# Protocol groups: voip itu-t_standard
# Wiki: http://www.protocolinfo.org/wiki/H.323
# Copyright (C) 2008 Matthew Strait, Ethan Sommer; See ../LICENSE
#
# This pattern is written without knowledge of the principles of H.323.
# It has only been tested with gnomemeeting and may not work for other
# clients. 
#
# Also, it has been reported that:
# "the pattern ... match[es] only first H.323 stream (conntrack for H.323 was 
# enabled).  Also the major chunk of traffic was of RTP which went untracked."
#
# Also, it may very well match other things that use
# Q.931. 

# Note that to take full advantage of this pattern, you will need to
# have connection tracking of H.323 support in your kernel.  This
# support is not in the stock kernel.  A patch can be found at
# http://netfilter.org

h323
# Q.931 format: http://www.freesoft.org/CIE/Topics/126.htm
# \x08  = Q.931
# . = length of call reference
# The next byte was: \x18 = message sent from originating side.
# But based on experimentation, it seems that just . is better. 
# .?.?.?.?.?.?.?.?.?.?.?.?.?.?.? = call reference (0-15 bytes (0 for nulls))
# \x05 = setup message
#
# Yup, it doesn't actually include any H.323 protocol information.
^\x08...?.?.?.?.?.?.?.?.?.?.?.?.?.?\x05
