package org.geoserver.rest.security.xml;

import org.geoserver.security.RequestFilterChain;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;
import java.util.ArrayList;
import java.util.List;

@XmlRootElement(name = "filterChains")
public class AuthFilterChainList {
    @XmlTransient
    List<AuthFilterChain> filterChains = new ArrayList<>();

    public AuthFilterChainList() {}

    public AuthFilterChainList(List<AuthFilterChain> filterChains) {
        this.filterChains = filterChains;
    }

    @XmlElement(name = "filterChain")
    public List<AuthFilterChain> getFilterChains() {
        return filterChains;
    }

    public void setFilterChains(List<AuthFilterChain> filterChains) {
        this.filterChains = filterChains;
    }
}
