package com.soauth.server.dao;

import com.soauth.core.model.SidebarTree;

import java.util.List;

/**
 * @author zhoujie
 * @date 2018/12/14
 */
public interface Admindao {

    /**
     * ���ع���Ա�˵���
     *
     * @param id
     * @return
     */
    List<SidebarTree> adminSidebar(Long id);
}
