#
# Copyright (c) 2015, Casey Schaufler <casey@schaufler-ca.com>
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer. 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# The views and conclusions contained in the software and documentation are
# those of the authors and should not be interpreted as representing official
# policies, either expressed or implied, of the FreeBSD Project.
#

PROGRAMS = \
	newsmack \
	smackecho smacktomux \
	smackin smackout \
	smackudsin smackudsout \
	smackspeedtest \
	smackpolyport \

default: ${PROGRAMS}

clean:
	rm -f ${PROGRAMS}

newsmack: newsmack.c smacktools.h
	cc -o newsmack newsmack.c

smackecho: smackecho.c smacktools.h
	cc -o smackecho smackecho.c

smackin: smackin.c smackrecvmsg.c smacktools.h
	cc -o smackin smackin.c smackrecvmsg.c

smackout: smackout.c smacktools.h
	cc -o smackout smackout.c

smackpolyport: smackpolyport.c smacktools.h
	cc -o smackpolyport smackpolyport.c

smackspeedtest: smackspeedtest.c
	cc -o smackspeedtest smackspeedtest.c

smacktomux: smacktomux.c smacktools.h
	cc -o smacktomux smacktomux.c

smackudsin: smackudsin.c smackrecvmsg.c smacktools.h
	cc -o smackudsin smackudsin.c smackrecvmsg.c

smackudsout: smackudsout.c smacktools.h
	cc -o smackudsout smackudsout.c
