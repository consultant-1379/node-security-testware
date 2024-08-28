package com.ericsson.nms.security.nscs.utils;

import com.ericsson.cifwk.taf.handlers.netsim.Cmd;
import com.ericsson.cifwk.taf.handlers.netsim.NetSimCommand;

@Cmd(value = ".show simne")
//TODO (ekeimoo): Why not use the one from TafNetsim and remove this class?
//TODO (ecappie): We'll go through this.
public final class ShowSimneCommand implements NetSimCommand {

}
