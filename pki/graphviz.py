"""Graphviz support for django-pki"""

from pki.settings import PKI_ENABLE_GRAPHVIZ, PKI_GRAPHVIZ_DIRECTION

if PKI_ENABLE_GRAPHVIZ is True:
    try:
        import pygraphviz as pgv
    except ImportError, e:
        raise Exception( "Failed to import pygraphviz. Disable PKI_ENABLE_GRAPHVIZ or install pygraphviz: %s" % e )

from pki.models import Certificate, CertificateAuthority

##------------------------------------------------------------------##
## Graphviz functions
##------------------------------------------------------------------##

def ObjectChain(object, target):
    """Render object chain PNG.
    
    Render a graphviz image for the given object and save the resulting PNG
    in target.
    """
    
    ## Create graph object
    G = pgv.AGraph(directed=True, layout="dot", pad="0.2", rankdir="TB")
    
    ## Determine shape on object instance
    if isinstance( object, Certificate):
        o_shape = "note"
    elif isinstance( object, CertificateAuthority):
        o_shape = "folder"
    else:
        raise Exception( "Invalid object instance given!" )
    
    ## Set fill color bases in state
    if object.active:
        obj_fill = "green3"
    else:
        obj_fill = "red"
    
    edges = []
    
    ## Add given object to graph
    G.add_node(object.common_name, shape=o_shape, style="filled, bold", fillcolor=obj_fill, fontcolor="white")
    
    ## Get parents if any
    if object.parent != None:
        
        ## Set p to objects parent
        p = object.parent
        
        ## Add parent node to graph
        if p.active:
            p_color = "green3"
        else:
            p_color = "red"
        
        G.add_node(p.common_name, shape="folder", color=p_color, style="bold")
        
        ## Set initial edge between requested onject and it's parent
        edges.append( [p.common_name, object.common_name] )
        
        while p != None:
            
            if p.active:
                col = "green3"
            else:
                col = "red"
            
            G.add_node(p.common_name, shape="folder", color=col, style="bold")
            
            if p.parent:
                edges.append( [p.parent.common_name, p.common_name] )
            
            p = p.parent
    
    ## Draw the edges
    for e in edges:
        G.add_edge( e[0], e[1] )
    
    G.layout()
    G.draw(target, format='png')
    
    return True

def ObjectTree(object, target):
    """Render object tree PNG.
    
    Render a graphviz image for the entire object tree object and save the resulting PNG
    in target.
    """
    
    ##-------------------------------------##
    ## Helper function for tree traversal
    ##-------------------------------------##
    def TraverseToBottom(r_id, graph=None):
        """Traverse the PKI tree down from a given id"""
        
        c = CertificateAuthority.objects.get(id=r_id)
        
        if c.subcas_allowed == True:
            x = CertificateAuthority.objects.filter(parent__id=c.pk)
        else:
            x = [c]
        
        for ca in x:
            
            if graph != None:
                if ca.active is True:
                    col = "green3"
                else:
                    col = "red"
                
                graph.add_node(ca.common_name, shape='folder', color=col, style="bold")
                
                ## Prevent link to self when this is a toplevel rootca with subcas_allowed=False
                if ca != c:
                    graph.add_edge(c.common_name, ca.common_name, color="black", weight="4.5")
            
            if ca.subcas_allowed == True:
                TraverseToBottom(ca.pk, graph)
            else:
                certs = Certificate.objects.filter(parent__id=ca.pk)
                
                if certs:
                    subgraph_list = [ ca.common_name ]
                    
                    for cert in certs:
                        
                        subgraph_list.append( cert.common_name )
                        
                        if graph != None:
                            if cert.active:
                                col = "green3"
                            else:
                                col = "red"
                            
                            graph.add_node(str(cert.common_name), shape='note', color=col, style="bold")
                            graph.add_edge(ca.common_name, cert.common_name, color="black", weight="4.5")
                    
                    sg = graph.subgraph(nbunch=subgraph_list, name="cluster_%d" % ca.pk, style='bold', color='black', label="")
    
    ##-------------------------------------##
    ## Object tree starts here
    ##-------------------------------------##
    
    ## Create graph object
    G = pgv.AGraph(directed=True, layout="dot", pad="0.2", ranksep="1.00", nodesep="0.10", rankdir=PKI_GRAPHVIZ_DIRECTION,)
                   #label="PKI Tree of CertificateAuthority \"%s\"" % str(object.common_name), labeljust="l", labelloc="t")
    
    if object.active: obj_fill = "green3"
    else: obj_fill = "red"
    
    G.add_node(object.common_name, shape='folder', style="filled,bold", fillcolor=obj_fill, fontcolor="white")
    
    if not isinstance(object, CertificateAuthority):
        raise Exception( "Object has to be of type CertificateAuthority, not %s" % object.__class__.__name__ )
    
    ## Find top parents
    if object.parent != None:
        p = object.parent
        
        while p != None:
            if p.parent == None:
                if p.active:
                    col = "green3"
                else:
                    col = "red"
                
                G.add_node(p.common_name, shape='folder', color=col, style="bold")
                TraverseToBottom(p.id, G)
            p = p.parent
    else:
        TraverseToBottom(object.id, G)
    
    G.layout()
    G.draw(target, format='png')
    
    return True
