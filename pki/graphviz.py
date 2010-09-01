"""Graphviz support for django-pki"""

try:
    import pygraphviz as pgv
except ImportError:
    raise Exception( "Failed to import pygraphviz. Disable PKI_ENABLE_GRAPHVIZ or install pygraphviz" )

from pki.models import Certificate, CertificateAuthority

def DepencyGraph(object, target, type):
    """Collect all objects in the depency tree and write Graphviz PNG"""
    
    if type == "cert":
        shape = "note"
    elif type == "ca":
        shape = "folder"
    else:
        raise Exception( "Invalid object type '%s' given!" % type )
    
    if object.active:
        obj_fill = "green3"
    else:
        obj_fill = "red"
    
    ## Initialize the object list
    obj_list = [ { 'name': object.common_name, 'state': object.active, 'fill': obj_fill, 'shape': shape }, ]
    
    ## Create graph object
    G = pgv.AGraph(directed=True, layout="dot", pad=0.2)
    
    ## Find possible parents
    if object.parent != None:
        p = object.parent
        
        while p != None:
            obj_list.append( { 'name': p.common_name, 'state': p.active, 'shape': 'folder' } )
            p = p.parent
    
    ## Reverse list to get a top-down tree
    obj_list.reverse()
    
    ## Add nodes to graph object
    for i in range(0, len(obj_list)):
        
        c = 'green3'
        if obj_list[i]['state'] is False:
            c = 'red'
        
        ## Add dummys in non root level
        if i > 0:
            if obj_list[i]['shape'] == 'note' or obj_list[i-1]['state'] is False:
                c_dummy = c
            else:
                c_dummy = 'black'
            
            G.add_node("dummy_start_%s" % obj_list[i]['name'], shape=obj_list[i]['shape'], color=c_dummy, label="...")
            G.add_node("dummy_end_%s" % obj_list[i]['name'], shape=obj_list[i]['shape'], color=c_dummy, label="...")
        
        if 'fill' in obj_list[i]:
            G.add_node(obj_list[i]['name'], shape=obj_list[i]['shape'], color="%s" % c, style="filled,bold", fillcolor=obj_list[i]['fill'], fontcolor="white")
        else:
            G.add_node(obj_list[i]['name'], shape=obj_list[i]['shape'], color="%s" % c, style="bold")
        
    ## Add edges to graph object
    for i in range(0, len(obj_list)-1):
        if obj_list[i+1]['state'] is False:
            color = "red"
        else:
            color = "green3"
        
        G.add_edge(obj_list[i]['name'], "dummy_start_%s" % obj_list[i+1]['name'], color="black", weight=4.5)
        G.add_edge(obj_list[i]['name'], obj_list[i+1]['name'], color="%s" % color, weight=5, style="bold")
        G.add_edge(obj_list[i]['name'], "dummy_end_%s" % obj_list[i+1]['name'], color="black", weight=4.5)
    
    G.layout()
    G.draw(target, format='png')
    
    return True

def ObjectTree(object, target):
    """Create full PKI tree for given CA object"""
    
    ## Create graph object
    G = pgv.AGraph(directed=True, layout="dot", pad=0.2)
    
    if object.active: obj_fill = "green3"
    else: obj_fill = "red"
    
    G.add_node(object.common_name, shape='folder', style="filled,bold", fillcolor=obj_fill, fontcolor="white")
    
    if object.__class__.__name__ != 'CertificateAuthority':
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
    
    print G.to_string()
    
    G.layout()
    G.draw(target, format='png')

def TraverseToBottom(r_id, graph=None):
    """Traverse the PKI tree down from a given id"""
    
    c = CertificateAuthority.objects.get(id=r_id)
    
    if c.subcas_allowed == True:
        x = CertificateAuthority.objects.filter(parent__id=c.pk)
        
        for ca in x:
            
            if graph != None:
                if ca.active is True:
                    col = "green3"
                else:
                    col = "red"
                
                graph.add_node(ca.name, shape='folder', color=col, style="bold")
                graph.add_edge(c.common_name, ca.common_name, color="black", weight=4.5)
            
            if ca.subcas_allowed == True:
                TraverseToBottom(ca.pk, graph)
            else:
                certs = Certificate.objects.filter(parent__id=ca.pk)
                
                for cert in certs:
                    
                    if graph != None:
                        if cert.active:
                            col = "green3"
                        else:
                            col = "red"
                        
                        graph.add_node(cert.common_name, shape='note', color=col, style="bold")
                        graph.add_edge(ca.common_name, cert.common_name, color="black", weight=4.5)


